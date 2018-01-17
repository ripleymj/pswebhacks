# LinuxFilter

## The Problem

Several vulnerabilities in WebLogic, and especially Struts, have been discovered
recently, and are frequently exploited among PeopleSoft users. All of the
published proof-of-concept code uploads a script, then executes it on the host.
This is frequently Python for Linux, and Powershell for Windows. Once an
attacker is inside a system running arbitrary code, it should be considered
completely compromised.

## Some background - the kernel

Since all of the published exploits rely on being able to execute uploaded code,
they could be interrupted by removing the ability of an attacker to run child
programs. The Linux seccomp framework gives us that ability. User programs
request kernel functionality through the use of some 300 system calls on Linux.
Seccomp allows us to give up our ability to use all 300, prior to any other
checks, like user permissions (root / UID 0), capabilities (CAP_SYS_ADMIN),
or a MAC LSM like SELinux. Because changing the seccomp policy is also a system
call, policy will frequently remove it as well, removing the ability of the
program or an attacker to modify the policy. Seccomp policy has three actions:
deny, kill, or allow. Deny will return an error to the calling application,
kill will end the offending program, and allow will continue evaluation of the
syscall through all the means (UID, MAC LSM, audit) that exist without seccomp.
Seccomp cannot grant functionality that would not have been granted without it.

You will frequently find references to seccomp in things like web browser
render processes, where you want to prevent parse errors in untrusted files
from causing damage to a system. They are also frequently applied to Docker-like
containers, where you want to be sure that the "root" user in a container does
not accidentally use its powers on the host system.

Seccomp has been in the Linux kernel for some time now, through three major
iterations.

### Seccomp version 1

Starting in kernel 2.6.12, you could write to /proc/PID/seccomp, which would
basically remove all syscall abililty except reading and writing to file
handles which had already been opened.

In 2.6.23, this functionality was moved to the prctl() syscall, and the /proc
interface was removed. Version 1 saw very limited use.

### Seccomp version 2

In kernel 3.5, the ability to specify your own functionality via a BPF program
was added, also via prctl(). You may remember the Berkeley Packet Filter (BPF)
from programs like tcpdump. BPF is a type of virtual machine that allows small,
provably safe programs to be loaded into the kernel. With tcpdump, these
programs match specified packets and forward them back to userland. With
seccomp, they match syscalls and allow or deny them. Because BPF operations
mainly consist of load, compare, and jump, you may recognize more as a type of
assembly language.

### Seccomp version 3

In kernel 3.17, the seccomp() syscall was added. The prctl() call was deemed to
be unwieldy, so seccomp() was created. In provides better handling for multi-
threaded applications.

### Linux distribution support

Because Linux distribution maintainers love to backport functionality, best
practice recommends probing for supported interfaces, rather than making
assumptions based on kernel version number. Seccomp is also a configurable
option at the time of kernel compilation, and can be removed. Unless you've
done something strange, this is the basic scene:

* RedHat Linux 6 - no usable support for seccomp.
* Oracle Linux 6 - version 3 via UEK4, no support in RHCK.
* RedHat Linux 7 - usable via version 2.
* Oracle Linux 7 - version 3 via UEK4, version 2 via RHCK.

### References

* https://en.wikipedia.org/wiki/Seccomp
* https://lwn.net/Articles/656307/
* https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

## Some background - prior art

My initial consideration was to use seccomp via systemd's SystemCallFilter
parameter. That was quickly ruled out as a non-starter, since several child
processes are started during WLS startup. By itself, startManagagedWeblogic.sh
would launch Java. In our environment, systemd controls NodeManager, which is
a shell script, launching Java, launching a shell script, launching Java.

For some reason, I remembered that Elasticsearch uses seccomp. As a fellow Java
application, which fortunately happens to be open-source, we can see how they
are achieving this. A quick Google search does not turn up many other
references, and most of them are centered around Android and their
implementation of "Java". Elasticsearch directly interfaces with seccomp via
the Java Native Access library. It also has tricks to restrict its abilities
via native functionality on Windows, Mac OS, and *BSD.

There is also the "Startup Class" functionality in WebLogic. Though I'd never
explored it, I started to wonder if Elasticsearch's example could be glued to
WLS. It turns out that, yes, it can.

### References

* https://www.freedesktop.org/software/systemd/man/systemd.exec.html
* https://www.elastic.co/guide/en/elasticsearch/reference/master/_system_call_filter_check.html
* https://github.com/elastic/elasticsearch/blob/master/server/src/main/java/org/elasticsearch/bootstrap/SystemCallFilter.java
* https://github.com/java-native-access/jna
* https://docs.oracle.com/cd/E72987_01/wls/WLACH/taskhelp/startup_shutdown/UseStartupAndShutdownClasses.html

## Caveats

This is a lab experiment. It is being published to start a conversation on how
to better defend applications. YOU ARE ULTIMATELY RESPONSIBLE FOR THE SECURITY
OF YOUR SYSTEMS! Analyze and experiment, then join the conversation. Do not
blindly trust something you found on the internet.

To the extent that this works, it is only possible on x86-64 Linux with a modern
kernel. It has been tried against PeopleTools 8.56 with Java 8. As Elasticsearch
has demonstrated, similar protections can be developed for other platforms from
within Java.

This is only capable of defending against attacks that use the current sequence
of steps where a script is uploaded and then executed. With a little creativity,
you can find alternate ways of attacking a system, such as running pure Java
code in the existing JVM instance, writing a crontab entry, or modifying
bashrc/bash_profile to execute on next login. None of these attacks are easily
addressable via seccomp.

This type of mitigation is only relevant to the web tier of PeopleSoft. App,
batch, and database all rely on process forking, though there may be other
syscalls you're willing to revoke. You will also need a much different loading
mechanism. This demo is not exclusive to PeopleSoft, and could load into any
WebLogic instance, but we can't make broad assumptions about the functionality
required for other apps hosted on WebLogic.

## A Solution

After SystemCallFilter.java has been extracted from Elasticsearch, some effort
is needed to scrub out the other operating systems, and cut dependencies on the
rest of the Elasticsearch code base. Constants.java is one of those remaining
dependencies.

Before doing any work with this in WebLogic, it should probably be moved to a
locally relevant Java package.

### Standalone Java

After cloning this repository, and changing into the LinuxFilter directory,
compile the Java classes like so:

```
javac -cp ../jna-4.5.1.jar Constants.java FilterTest.java SystemCallFilter.java
```

The FilterTest program can now be run like this:

```
java -cp ../jna-4.5.1.jar:. FilterTest
```
```
total 0
drwxr-xr-x 2 ripleymj ripleymj 18 Jan 15 22:52 hsperfdata_ripleymj
drwxr-xr-x 2 ripleymj ripleymj  6 Jan 14 11:20 jna--1175144892
Done: 0
Linux seccomp filter installation successful, threads: all
Exception in thread "main" java.io.IOException: Cannot run program "ls": error=13, Permission denied
        at java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)
        at FilterTest.main(FilterTest.java:19)
Caused by: java.io.IOException: error=13, Permission denied
        at java.lang.UNIXProcess.forkAndExec(Native Method)
        at java.lang.UNIXProcess.<init>(UNIXProcess.java:247)
        at java.lang.ProcessImpl.start(ProcessImpl.java:134)
        at java.lang.ProcessBuilder.start(ProcessBuilder.java:1029)
        ... 1 more
```

Inside FilterTest.java, ProcessBuilder runs `ls -l /tmp` and prints the output.
On line #17, seccomp is invoked to drop privileges. After the filter is
installed, `ls -l /tmp` is attempted again. If seccomp was successful, this
will fail.

### WebLogic

If you have exploit code for WebLogic, or even the proof-of-concept code, now
would be a good time to go get it. If you want to play it safe, take exec.jsp
from this repository and copy it to the PORTAL.war directory on a web server.
Now browse http://peoplehost.peopledomain:8000/exec.jsp and it should produce a
listing of the contents of your /tmp directory.

Now you need to compile and package the syscall filter. Compile:

```
javac -cp ../jna-4.5.1.jar Constants.java SystemCallFilter.java
```

and package:

```
jar cvf syscallfilter.jar *class
```
```
added manifest
adding: Constants.class(in = 2107) (out= 1243)(deflated 41%)
adding: SystemCallFilter$Arch.class(in = 546) (out= 370)(deflated 32%)
adding: SystemCallFilter.class(in = 7503) (out= 3504)(deflated 53%)
adding: SystemCallFilter$LinuxLibrary.class(in = 473) (out= 248)(deflated 47%)
adding: SystemCallFilter$SockFilter.class(in = 439) (out= 312)(deflated 28%)
adding: SystemCallFilter$SockFProg.class(in = 1509) (out= 869)(deflated 42%)
```

Copy `syscallfilter.jar` and `jna-4.5.1.jar` to `.../webserv/peoplesoft/lib/`.
Now browse to the WebLogic Admin Console, and select
"Startup And Shutdown Classes" from the home page.

* Lock and Edit
* Select New
* Startup Class
* Give it a fun name and specify your.package.name.SystemCallFilter
* Target it to your favorite collection of servers

After the wizard completes, open the item to edit advanced properties. If you're
depending on this, "Failure is Fatal" is probably a good idea, so the server
won't start without protection. For development, this is probably bad. Checking
"Run Before Application Deployments" and "Run Before Application Activations"
are both good ideas for maximum protection.

That's it. Activate Changes and bounce WebLogic. When it returns, try browsing
to exec.jsp or using exploit code again. You should get an HTTP Error 500 now,
and in the log files, a more verbose version of the error from the command line.

```
####<Jan 14, 2018 1:42:56 PM EST> <Error> <HTTP> <olzfs92u26> <PIA> <[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <ebf8ead6-8ce2-4814-8d7f-fa70cef14495-00000012> <1515955376752> <[severity-value: 8] [rid: 0] [partition-id: 0] [partition-name: DOMAIN] > <BEA-101019> <[ServletContext@201529124[app:peoplesoft module:/ path:null spec-version:3.1]] Servlet failed with an IOException.
java.io.IOException: Cannot run program "ls": error=13, Permission denied
        at java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)
        at jsp_servlet.__exec._jspService(__exec.java:84)
        at weblogic.servlet.jsp.JspBase.service(JspBase.java:35)
        at weblogic.servlet.internal.StubSecurityHelper$ServletServiceAction.run(StubSecurityHelper.java:286)
        at weblogic.servlet.internal.StubSecurityHelper$ServletServiceAction.run(StubSecurityHelper.java:260)
        at weblogic.servlet.internal.StubSecurityHelper.invokeServlet(StubSecurityHelper.java:137)
        at weblogic.servlet.internal.ServletStubImpl.execute(ServletStubImpl.java:350)
        at weblogic.servlet.internal.ServletStubImpl.onAddToMapException(ServletStubImpl.java:489)
        at weblogic.servlet.internal.ServletStubImpl.execute(ServletStubImpl.java:376)
        at weblogic.servlet.internal.TailFilter.doFilter(TailFilter.java:25)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at weblogic.websocket.tyrus.TyrusServletFilter.doFilter(TyrusServletFilter.java:266)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at psft.pt8.psfilter.doFilter(psfilter.java:109)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at weblogic.servlet.internal.WebAppServletContext$ServletInvocationAction.wrapRun(WebAppServletContext.java:3654)
        at weblogic.servlet.internal.WebAppServletContext$ServletInvocationAction.run(WebAppServletContext.java:3620)
        at weblogic.security.acl.internal.AuthenticatedSubject.doAs(AuthenticatedSubject.java:326)
        at weblogic.security.service.SecurityManager.runAsForUserCode(SecurityManager.java:196)
        at weblogic.servlet.provider.WlsSecurityProvider.runAsForUserCode(WlsSecurityProvider.java:203)
        at weblogic.servlet.provider.WlsSubjectHandle.run(WlsSubjectHandle.java:71)
        at weblogic.servlet.internal.WebAppServletContext.doSecuredExecute(WebAppServletContext.java:2423)
        at weblogic.servlet.internal.WebAppServletContext.securedExecute(WebAppServletContext.java:2280)
        at weblogic.servlet.internal.WebAppServletContext.execute(WebAppServletContext.java:2258)
        at weblogic.servlet.internal.ServletRequestImpl.runInternal(ServletRequestImpl.java:1626)
        at weblogic.servlet.internal.ServletRequestImpl.run(ServletRequestImpl.java:1586)
        at weblogic.servlet.provider.ContainerSupportProviderImpl$WlsRequestExecutor.run(ContainerSupportProviderImpl.java:270)
        at weblogic.invocation.ComponentInvocationContextManager._runAs(ComponentInvocationContextManager.java:348)
        at weblogic.invocation.ComponentInvocationContextManager.runAs(ComponentInvocationContextManager.java:333)
        at weblogic.work.LivePartitionUtility.doRunWorkUnderContext(LivePartitionUtility.java:54)
        at weblogic.work.PartitionUtility.runWorkUnderContext(PartitionUtility.java:41)
        at weblogic.work.SelfTuningWorkManagerImpl.runWorkUnderContext(SelfTuningWorkManagerImpl.java:617)
        at weblogic.work.ExecuteThread.execute(ExecuteThread.java:397)
        at weblogic.work.ExecuteThread.run(ExecuteThread.java:346)
Caused By: java.io.IOException: error=13, Permission denied
        at java.lang.UNIXProcess.forkAndExec(Native Method)
        at java.lang.UNIXProcess.<init>(UNIXProcess.java:247)
        at java.lang.ProcessImpl.start(ProcessImpl.java:134)
        at java.lang.ProcessBuilder.start(ProcessBuilder.java:1029)
        at jsp_servlet.__exec._jspService(__exec.java:84)
        at weblogic.servlet.jsp.JspBase.service(JspBase.java:35)
        at weblogic.servlet.internal.StubSecurityHelper$ServletServiceAction.run(StubSecurityHelper.java:286)
        at weblogic.servlet.internal.StubSecurityHelper$ServletServiceAction.run(StubSecurityHelper.java:260)
        at weblogic.servlet.internal.StubSecurityHelper.invokeServlet(StubSecurityHelper.java:137)
        at weblogic.servlet.internal.ServletStubImpl.execute(ServletStubImpl.java:350)
        at weblogic.servlet.internal.ServletStubImpl.onAddToMapException(ServletStubImpl.java:489)
        at weblogic.servlet.internal.ServletStubImpl.execute(ServletStubImpl.java:376)
        at weblogic.servlet.internal.TailFilter.doFilter(TailFilter.java:25)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at weblogic.websocket.tyrus.TyrusServletFilter.doFilter(TyrusServletFilter.java:266)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at psft.pt8.psfilter.doFilter(psfilter.java:109)
        at weblogic.servlet.internal.FilterChainImpl.doFilter(FilterChainImpl.java:78)
        at weblogic.servlet.internal.WebAppServletContext$ServletInvocationAction.wrapRun(WebAppServletContext.java:3654)
        at weblogic.servlet.internal.WebAppServletContext$ServletInvocationAction.run(WebAppServletContext.java:3620)
        at weblogic.security.acl.internal.AuthenticatedSubject.doAs(AuthenticatedSubject.java:326)
        at weblogic.security.service.SecurityManager.runAsForUserCode(SecurityManager.java:196)
        at weblogic.servlet.provider.WlsSecurityProvider.runAsForUserCode(WlsSecurityProvider.java:203)
        at weblogic.servlet.provider.WlsSubjectHandle.run(WlsSubjectHandle.java:71)
        at weblogic.servlet.internal.WebAppServletContext.doSecuredExecute(WebAppServletContext.java:2423)
        at weblogic.servlet.internal.WebAppServletContext.securedExecute(WebAppServletContext.java:2280)
        at weblogic.servlet.internal.WebAppServletContext.execute(WebAppServletContext.java:2258)
        at weblogic.servlet.internal.ServletRequestImpl.runInternal(ServletRequestImpl.java:1626)
        at weblogic.servlet.internal.ServletRequestImpl.run(ServletRequestImpl.java:1586)
        at weblogic.servlet.provider.ContainerSupportProviderImpl$WlsRequestExecutor.run(ContainerSupportProviderImpl.java:270)
        at weblogic.invocation.ComponentInvocationContextManager._runAs(ComponentInvocationContextManager.java:348)
        at weblogic.invocation.ComponentInvocationContextManager.runAs(ComponentInvocationContextManager.java:333)
        at weblogic.work.LivePartitionUtility.doRunWorkUnderContext(LivePartitionUtility.java:54)
        at weblogic.work.PartitionUtility.runWorkUnderContext(PartitionUtility.java:41)
        at weblogic.work.SelfTuningWorkManagerImpl.runWorkUnderContext(SelfTuningWorkManagerImpl.java:617)
        at weblogic.work.ExecuteThread.execute(ExecuteThread.java:397)
        at weblogic.work.ExecuteThread.run(ExecuteThread.java:346)
>
```

### References

* https://docs.oracle.com/cd/E72987_01/wls/WLACH/taskhelp/startup_shutdown/UseStartupAndShutdownClasses.html
