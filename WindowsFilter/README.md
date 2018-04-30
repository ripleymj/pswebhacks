# WindowsFilter

## The Problem

Several vulnerabilities in WebLogic, and especially Struts, have been discovered
recently, and are frequently exploited among PeopleSoft users. Much of the
published proof-of-concept code uploads a script, then executes it on the host.
This is frequently Python for Linux, and Powershell for Windows. Once an
attacker is inside a system running arbitrary code, it should be considered
completely compromised.

## Some background - prior art

For some reason, I remembered that Elasticsearch attempts to restrict remote
code execution. As a fellow Java application, which fortunately happens to be
open-source, we can see how they are achieving this.

WebLogic contains "Startup Class" functionality, and though I'd never
explored it, I started to wonder if Elasticsearch's example could be glued to
WLS. It turns out that, yes, it can.

### References

* https://www.elastic.co/guide/en/elasticsearch/reference/master/_system_call_filter_check.html
* https://github.com/elastic/elasticsearch/blob/master/server/src/main/java/org/elasticsearch/bootstrap/SystemCallFilter.java
* https://github.com/java-native-access/jna
* https://docs.oracle.com/cd/E72987_01/wls/WLACH/taskhelp/startup_shutdown/UseStartupAndShutdownClasses.html
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms684147(v=vs.85).aspx

## Caveats

This is a lab experiment. It is being published to start a conversation on how
to better defend applications. YOU ARE ULTIMATELY RESPONSIBLE FOR THE SECURITY
OF YOUR SYSTEMS! Analyze and experiment, then join the conversation. Do not
blindly trust something you found on the internet.

To the extent that this works, it is only possible on Windows. It has been
tried against PeopleTools 8.56 with Java 8. As Elasticsearch has demonstrated,
similar protections can be developed for other platforms from within Java.

This is only capable of defending against attacks that use the current sequence
of steps where a script is uploaded and then executed. With a little creativity,
you can find alternate ways of attacking a system, such as running pure Java
code in the existing JVM instance. None of these attacks are easily
addressable with this mitigation

This type of mitigation is only relevant to the web tier of PeopleSoft. App,
batch, and database all rely on process forking. You will also need a much
different loading mechanism. This demo is not exclusive to PeopleSoft, and
could load into any WebLogic instance, but we can't make broad assumptions
about the functionality required for other apps hosted on WebLogic.

## A Solution

After SystemCallFilter.java has been extracted from Elasticsearch, some effort
is needed to scrub out the other operating systems, and cut dependencies on the
rest of the Elasticsearch code base. Constants.java is one of those remaining
dependencies.

Before doing any work with this in WebLogic, it should probably be moved to a
locally relevant Java package.

### Standalone Java

After cloning this repository, and changing into the WindowsFilter directory,
compile the Java classes like so:

```
javac -cp ..\jna-4.5.1.jar *java
```

The FilterTest program can now be run like this:

```
java -cp ..\jna-4.5.1.jar;. FilterTest
```
```
 Volume in drive C has no label.
 Volume Serial Number is 7ADB-A96F

 Directory of C:\Users\ripleymj\Documents\GitHub\pswebhacks\WindowsFilter

04/30/2018  11:59 AM    <DIR>          .
04/30/2018  11:59 AM    <DIR>          ..
04/30/2018  12:01 PM               201 ConsoleCtrlHandler.class
01/19/2018  02:11 PM             1,157 ConsoleCtrlHandler.java
04/30/2018  12:01 PM             2,107 Constants.class
01/19/2018  02:11 PM             3,627 Constants.java
01/19/2018  11:49 AM               452 exec-win.jsp
04/30/2018  12:01 PM             1,393 FilterTest.class
04/30/2018  12:01 PM               758 FilterTest.java
04/30/2018  12:01 PM               202 JNAKernel32Library$1.class
04/30/2018  12:01 PM               546 JNAKernel32Library$Holder.class
04/30/2018  12:01 PM             1,080 JNAKernel32Library$JOBOBJECT_BASIC_LIMIT_
INFORMATION.class
04/30/2018  12:01 PM               894 JNAKernel32Library$MemoryBasicInformation
.class
04/30/2018  12:01 PM             1,077 JNAKernel32Library$NativeHandlerCallback.
class
04/30/2018  12:01 PM               419 JNAKernel32Library$SizeT.class
04/30/2018  12:01 PM             3,480 JNAKernel32Library.class
01/19/2018  02:11 PM            11,870 JNAKernel32Library.java
01/19/2018  03:04 PM             8,740 syscallfilter.jar
04/30/2018  12:01 PM             2,415 SystemCallFilter.class
01/19/2018  03:04 PM             3,203 SystemCallFilter.java
              18 File(s)         43,621 bytes
               2 Dir(s)  167,814,983,680 bytes free
Done: 0
windows/Kernel32 library loaded
Windows ActiveProcessLimit initialization successful
Exception in thread "main" java.io.IOException: Cannot run program "cmd": Create
Process error=1816, Not enough quota is available to process this command
        at java.base/java.lang.ProcessBuilder.start(Unknown Source)
        at java.base/java.lang.ProcessBuilder.start(Unknown Source)
        at FilterTest.main(FilterTest.java:20)
Caused by: java.io.IOException: CreateProcess error=1816, Not enough quota is av
ailable to process this command
        at java.base/java.lang.ProcessImpl.create(Native Method)
        at java.base/java.lang.ProcessImpl.<init>(Unknown Source)
        at java.base/java.lang.ProcessImpl.start(Unknown Source)
        ... 3 more
```

Inside FilterTest.java, ProcessBuilder runs `cmd /c dir` and prints the output.
On line #18, ActiveProcessLimit is set. After the limit is set, `cmd /c dir` is
attempted again. If the limit was successful, this will fail.

### WebLogic

If you have exploit code for WebLogic, or even the proof-of-concept code, now
would be a good time to go get it. If you want to play it safe, take
`exec-win.jsp` from this repository and copy it to the PORTAL.war directory on
a web server. Now browse http://peoplehost.peopledomain:8000/exec-win.jsp and
it should produce a listing of the contents of your C:\ drive.

Now you need to compile and package the syscall filter. Compile:

```
javac -cp ..\jna-4.5.1.jar *java
```

and package:

```
jar.exe cvf syscallfilter.jar *class
```
```
added manifest
adding: ConsoleCtrlHandler.class(in = 201) (out= 163)(deflated 18%)
adding: Constants.class(in = 2107) (out= 1243)(deflated 41%)
adding: FilterTest.class(in = 1393) (out= 783)(deflated 43%)
adding: JNAKernel32Library$1.class(in = 202) (out= 156)(deflated 22%)
adding: JNAKernel32Library$Holder.class(in = 546) (out= 329)(deflated 39%)
adding: JNAKernel32Library$JOBOBJECT_BASIC_LIMIT_INFORMATION.class(in = 1080) (out= 637)(deflated 41%)
adding: JNAKernel32Library$MemoryBasicInformation.class(in = 894) (out= 538)(deflated 39%)
adding: JNAKernel32Library$NativeHandlerCallback.class(in = 1077) (out= 587)(deflated 45%)
adding: JNAKernel32Library$SizeT.class(in = 419) (out= 300)(deflated 28%)
adding: JNAKernel32Library.class(in = 3480) (out= 1615)(deflated 53%)
adding: SystemCallFilter.class(in = 2415) (out= 1265)(deflated 47%)
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
to exec-win.jsp or using exploit code again. You should get an HTTP Error 500 now,
and in the log files, a more verbose version of the error from the command line.

When WebLogic starts, you may notice something like this in the logs:

```
<Apr 30, 2018 2:49:38 PM EDT> <Notice> <Security> <BEA-090082> <Security initializing using security realm myrealm.>
windows/Kernel32 library loaded
Windows ActiveProcessLimit initialization successful
<Apr 30, 2018 2:49:44 PM EDT> <Notice> <WebLogicServer> <BEA-000365> <Server state changed to STANDBY.>
```

```
Error 500--Internal Server Error

java.io.IOException: Cannot run program "cmd": CreateProcess error=1816, Not enough quota is available to process this command
	at java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)
	at jsp_servlet.__exec_45_win._jspService(__exec_45_win.java:81)
	at weblogic.servlet.jsp.JspBase.service(JspBase.java:35)
```

### References

* https://docs.oracle.com/cd/E72987_01/wls/WLACH/taskhelp/startup_shutdown/UseStartupAndShutdownClasses.html
