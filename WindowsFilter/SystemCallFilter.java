
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

import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * Installs a system call filter to block process execution.
 * <p>
 * On Windows, process creation is restricted with
 * {@code SetInformationJobObject/ActiveProcessLimit}.
 * <p>
 * This is not intended as a sandbox. It is another level of security, mostly
 * intended to annoy security researchers and make their lives more difficult in
 * achieving "remote execution" exploits.
 */
// not an example of how to write code!!!
public class SystemCallFilter {

	// windows impl via job ActiveProcessLimit
	public static void main(String[] args) {

		if (!Constants.WINDOWS) {
			throw new IllegalStateException(
					"bug: should not be trying to initialize ActiveProcessLimit for an unsupported OS");
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
			// modify the number of active processes to be 1 (exactly the one process we
			// will add to the job).
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

		doLog("Windows ActiveProcessLimit initialization successful");
	}

	static void doLog(String input) {
		System.out.println(input);
	}
}
