package no.uis.portal.feidelogin.web;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import no.uis.portal.feidelogin.FeideHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FeideFilter implements Filter {
	
	private static Log log = LogFactory.getLog(FeideFilter.class);


	private FilterConfig filterConfig = null;

	@Override
	public void destroy() {
		this.filterConfig = null;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain fc) throws IOException, ServletException {

		log.info("FeideFilter.doFilter: called");
		HttpServletRequest hreq = (HttpServletRequest)servletRequest;
		HttpServletResponse hresp = (HttpServletResponse)servletResponse;

		setupFilter();

		if (!authenticated(hreq) && !allow(hreq.getServletPath())) {
			hreq.getSession().setAttribute("originalRequest", getFullApplicationPath(hreq)+hreq.getServletPath());
			redirect(hreq, hresp, Constants.AUTH_LOGIN_SERVLET);
			return;
		}		
		log.debug("FeideFilter.doFilter: chaining filter");
		fc.doFilter(servletRequest, servletResponse);

	}

	private boolean allow(String uri) {
		log.debug("FeideFilter.allow: Should we allow "+uri+" based on comparison to ("+Constants.AUTH_LOGIN_SERVLET+"|"+Constants.AUTH_LOGOUT_SERVLET+")");
		if (uri.equals(Constants.AUTH_LOGIN_SERVLET) || uri.equals(Constants.AUTH_LOGOUT_SERVLET))
			return true;
		return false;
	}

	private boolean authenticated(HttpServletRequest req) {

		HttpSession session = req.getSession(false);
        
		if (session == null)
        	return false;
		
		String userId = (String)session.getAttribute(Constants.USER_ID_ATTRIBUTE);

		log.debug("FeideFilter.authenticated: userId="+userId);
		if (userId == null)
			return false;
		
		return true;
	}

	private void redirect(HttpServletRequest hreq, HttpServletResponse hresp, String servlet) throws IOException {

		if (hreq.getCharacterEncoding() == null) {
			String defaultEncoding =  getInitParam(Constants.FILTER_ENCODING);
			if (defaultEncoding == null)
				defaultEncoding = "UTF-8";
				
			hreq.setCharacterEncoding(defaultEncoding);
		}

		String redirectUrl = completeUrl(hreq, servlet);

		// TODO relaystate?

		log.debug("FeideFilter.redirect: redirecting to "+redirectUrl);
		hresp.sendRedirect(hresp.encodeRedirectURL(redirectUrl));
	}

    public static String getFullApplicationPath(HttpServletRequest request){
        
        StringBuffer sb = new StringBuffer();
        sb.append("http");
        if(request.isSecure()) {
            sb.append("s");
        }
        sb.append("://");
        sb.append(request.getServerName());
        sb.append(":");
        sb.append(request.getServerPort());
        sb.append(request.getContextPath());
        return sb.toString();
    }

    private String completeUrl(HttpServletRequest req, String redirectUri) {
    	return getFullApplicationPath(req) + redirectUri; 
/*
		String reqUrl = req.getRequestURL().toString();

		if (redirectUri != null) {
			if (!reqUrl.endsWith("/"))
				reqUrl += "/";
			reqUrl += redirectUri;
		}

		String queryString = req.getQueryString();
		String sepChar = "?";

		if (reqUrl.contains("?"))
			sepChar = "&";

		if (queryString != null) {
			reqUrl += sepChar + queryString;
		}

		return reqUrl;
		*/
	}

	private String getInitParam(String parameterName){
		return filterConfig.getServletContext().getInitParameter(parameterName);
	}

	private void setupFilter() {
		
		// TODO validate configuration

	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

}
