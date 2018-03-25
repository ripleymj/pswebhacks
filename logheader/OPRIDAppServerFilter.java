import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import psft.pt8.jb.JBEntry;
import psft.pt8.util.PSSessionProp;

@WebFilter(filterName = "SimpleFilter",
		urlPatterns = { "/psp/*", "/psc/*" })

public class SimpleFilter implements Filter
{
	private FilterConfig filterConfig;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException
	{
		this.filterConfig = filterConfig;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException
	{
		ServletContext servletContext = filterConfig.getServletContext();

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		HttpSession session = request.getSession(false);

		if (session != null)
		{
			if (session.getAttribute("USERID") != null)
			{
				response.addHeader("X-PS-USERID", session.getAttribute("USERID").toString());
			}

			String sessionPropsName = null;
			for (Enumeration<String> e = session.getAttributeNames(); e.hasMoreElements();)
			{
				String element = e.nextElement();
				if (element.startsWith("portalSessionProps"))
				{
					sessionPropsName = element;
					servletContext.log("MJR Found portalSession: " + sessionPropsName);
				}
			}

			if (sessionPropsName != null && session.getAttribute(sessionPropsName) != null)
			{
				PSSessionProp props = (PSSessionProp) session.getAttribute(sessionPropsName);

				JBEntry jbe = (JBEntry) props.get("JBridge");
				if (jbe != null)
				{
					response.addHeader("X-PS-APPSERVER", jbe.getSession().getCurrentAppServer());
				}
			}
		}

		filterChain.doFilter(servletRequest, servletResponse);
	}

	@Override
	public void destroy()
	{
		filterConfig = null;
	}
}
