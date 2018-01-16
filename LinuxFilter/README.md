# LinuxFilter

## The Problem

Several vulnerabilities in WebLogic, and especially Struts, have been discovered
recently, and are frequently exploited among PeopleSoft users. All of the
published proof-of-concept code uploads a script, then executes it on the host.
This is frequently Python for Linux, and Powershell for Windows. Once an
attacker is inside the system running arbitrary code, it should be considered
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
program or an attacker to modify the policy.

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
interface was removed. This version saw very limited use.

### Seccomp version 2

In kernel 3.5, the ability to specify your own functionality via a BPF program
was added, also via prctl(). You may remember the Berkeley Packet Filter (BPF)
from programs like tcpdump. BPF is a type of virtual machine that allows small,
provably safe programs to be loaded into the kernel. With tcpdump, they match
specified packets and forward them back to userland. With seccomp, they match
syscalls and allow or deny them. Because its operations mainly consist of load,
compare, and jump you may recognize more as a type of assembly language.

### Seccomp version 3

In kernel 3.17, the seccomp() syscall was added. The prctl() call was deemed to
be unwieldy, so seccomp() was created. In provides better handling for multi-
threaded applications.

### Distro support

Because Linux distribution maintainers love to backport functionality, best
practice recommends probing for supported interfaces, rather than making
assumptions based on kernel version number. Unless you've done something
strange, this is the basic scene:

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
application, that fortunately happens to be open-source, I was curious how they
were achieving this. A quick Google search does not turn up many other
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

## A Solution

