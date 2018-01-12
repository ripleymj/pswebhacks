/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
//import org.apache.lucene.util.Constants;
//import org.apache.lucene.util.IOUtils;
//import org.elasticsearch.common.logging.Loggers;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * Installs a system call filter to block process execution.
 * <p>
 * This is supported on Linux and Windows.
 * <p>
 * On Linux it currently supports amd64 and i386 architectures, requires Linux kernel 3.5 or above, and requires
 * {@code CONFIG_SECCOMP} and {@code CONFIG_SECCOMP_FILTER} compiled into the kernel.
 * <p>
 * On Linux BPF Filters are installed using either {@code seccomp(2)} (3.17+) or {@code prctl(2)} (3.5+). {@code seccomp(2)}
 * is preferred, as it allows filters to be applied to any existing threads in the process, and one motivation
 * here is to protect against bugs in the JVM. Otherwise, code will fall back to the {@code prctl(2)} method
 * which will at least protect elasticsearch application threads.
 * <p>
 * Linux BPF filters will return {@code EACCES} (Access Denied) for the following system calls:
 * <ul>
 *   <li>{@code execve}</li>
 *   <li>{@code fork}</li>
 *   <li>{@code vfork}</li>
 *   <li>{@code execveat}</li>
 * </ul>
 * <p>
 * On Windows, process creation is restricted with {@code SetInformationJobObject/ActiveProcessLimit}.
 * <p>
 * This is not intended as a sandbox. It is another level of security, mostly intended to annoy
 * security researchers and make their lives more difficult in achieving "remote execution" exploits.
 * @see <a href="http://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt">
 *      http://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt</a>
 * @see <a href="https://reverse.put.as/wp-content/uploads/2011/06/The-Apple-Sandbox-BHDC2011-Paper.pdf">
 *      https://reverse.put.as/wp-content/uploads/2011/06/The-Apple-Sandbox-BHDC2011-Paper.pdf</a>
 * @see <a href="https://docs.oracle.com/cd/E23824_01/html/821-1456/prbac-2.html">
 *      https://docs.oracle.com/cd/E23824_01/html/821-1456/prbac-2.html</a>
 */
// not an example of how to write code!!!
final class SystemCallFilter {
    private static final Logger logger = LogManager.getLogger(SystemCallFilter.class);


    // windows impl via job ActiveProcessLimit

    static void windowsImpl() {
        if (!Constants.WINDOWS) {
            throw new IllegalStateException("bug: should not be trying to initialize ActiveProcessLimit for an unsupported OS");
        }

        JNAKernel32Library lib = JNAKernel32Library.getInstance();

        // create a new Job
        Pointer job = lib.CreateJobObjectW(null, null);
        if (job == null) {
            throw new UnsupportedOperationException("CreateJobObject: " + Native.getLastError());
        }

        try {
            // retrieve the current basic limits of the job
            int clazz = JNAKernel32Library.JOBOBJECT_BASIC_LIMIT_INFORMATION_CLASS;
            JNAKernel32Library.JOBOBJECT_BASIC_LIMIT_INFORMATION limits = new JNAKernel32Library.JOBOBJECT_BASIC_LIMIT_INFORMATION();
            limits.write();
            if (!lib.QueryInformationJobObject(job, clazz, limits.getPointer(), limits.size(), null)) {
                throw new UnsupportedOperationException("QueryInformationJobObject: " + Native.getLastError());
            }
            limits.read();
            // modify the number of active processes to be 1 (exactly the one process we will add to the job).
            limits.ActiveProcessLimit = 1;
            limits.LimitFlags = JNAKernel32Library.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.write();
            if (!lib.SetInformationJobObject(job, clazz, limits.getPointer(), limits.size())) {
                throw new UnsupportedOperationException("SetInformationJobObject: " + Native.getLastError());
            }
            // assign ourselves to the job
            if (!lib.AssignProcessToJobObject(job, lib.GetCurrentProcess())) {
                throw new UnsupportedOperationException("AssignProcessToJobObject: " + Native.getLastError());
            }
        } finally {
            lib.CloseHandle(job);
        }

        logger.debug("Windows ActiveProcessLimit initialization successful");
    }

    /**
     * Attempt to drop the capability to execute for the process.
     * <p>
     * This is best effort and OS and architecture dependent. It may throw any Throwable.
     * @return 0 if we can do this for application threads, 1 for the entire process
     */
    static int init(Path tmpFile) throws Exception {
        if (Constants.WINDOWS) {
            windowsImpl();
            return 1;
        } else {
            throw new UnsupportedOperationException("syscall filtering not supported for OS: '" + Constants.OS_NAME + "'");
        }
    }
}
