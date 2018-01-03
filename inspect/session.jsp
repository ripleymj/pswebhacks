<%@ page import="java.io.*,java.util.*,java.lang.reflect.Method,psft.pt8.jb.JBEntry,psft.pt8.net.NetSession" %>

<%!
void printMethods(JspWriter out, Object object) throws IOException
{
	Method[] methods = object.getClass().getMethods();
	for(Method m:methods)
	{
		if(m.getDeclaringClass() == object.getClass())
		{
			out.println(m.toGenericString() + "<br /><br />");
		}
	}
}
%>

<!DOCTYPE html>
<html>
<body>
<h2>Session data</h2>
<table border="1">
<tr><th>Name</th><th>Type</th><th>Data</th></tr>
<%
Enumeration keys = session.getAttributeNames();
while (keys.hasMoreElements())
{
	out.println("<tr>");
	String key = (String)keys.nextElement();
	Object o = session.getAttribute(key);
	out.println("<td>" + key + "</td>");
	out.println("<td>" + o.getClass().getSuperclass().getName() + " --> " + o.getClass().getName() + "</td>");
	out.println("<td>" + o + "</td>");
	out.println("</tr>");
}
%>
</table>
<hr />
<%
Hashtable sessionProps = null;
for (Enumeration<String> e = session.getAttributeNames(); e.hasMoreElements();)
{
	String element = e.nextElement();
	if (element.startsWith("portalSessionProps"))
	{
		sessionProps = (Hashtable) session.getAttribute(element);
		out.println("<h3>Proceeding with session: " + element + "</h3>");
	}
}

out.println("<hr />");

if(sessionProps != null)
{
	out.println("<h2>portalSessionProps</h2>");
	out.println("<table border=\"1\"><tr><th>Key</th><th>Value</th></tr>");
	for (Enumeration<Object> e = sessionProps.keys(); e.hasMoreElements();)
	{
		Object element = e.nextElement();
		out.println("<tr><td>" + element + "</td>");
		out.println("<td>" + sessionProps.get(element) + "</td></tr>");
	}
	out.println("</table>");

	out.println("<h2>portalSessionProps Methods</h2>");
	printMethods(out, sessionProps);

	out.println("<hr />");
	out.println("<h2>JBridge methods</h2>");

	Object jbridge = ((Properties)sessionProps).get("JBridge");
	printMethods(out, jbridge);

	out.println("<hr />");
	out.println("<h2>JBSession methods</h2>");

	JBEntry jb = ((psft.pt8.jb.JBEntry)jbridge);
	printMethods(out, jb.getSession());

	out.println("<hr />");
	out.println("<h2>NetSession</h2>");

	NetSession ns = (psft.pt8.net.NetSession) jb.getSession();

	//out.println("Server URL: " + ns.getServerURL());
	out.println("Current appserver: " + ns.getCurrentAppServer());

	response.setHeader("X-PS-AppServer", ns.getCurrentAppServer());
}
else
{
	out.println("portalSessionProps is null, log in to PeopleSoft");
}
%>
</body>
</html>
