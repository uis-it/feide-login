package no.uis.portal.feidelogin.web;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;

import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import no.uis.portal.feidelogin.FeideHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FeideAuthenticator extends HttpServlet implements Servlet {
	private static Log log = LogFactory.getLog(FeideAuthenticator.class);

	private static final long serialVersionUID = -4295079485421401479L;
	
	private WebFeideHandler feideHandler;
	private String feideLogoutPath = Constants.FEIDE_LOGOUT_PATH_DEFAULT;
	private String feideLoginPath = Constants.FEIDE_LOGIN_PATH_DEFAULT;

	@Override
  public void init() throws ServletException {
	  ServletContext servletContext = getServletContext();
    feideHandler = new WebFeideHandler(servletContext);
	  String param = servletContext.getInitParameter(Constants.PARAM_FEIDE_LOGIN_PATH);
	  if (param != null) {
	    feideLoginPath = param;
	  }
	  param = servletContext.getInitParameter("feideLogoutPath");
	  if (param != null) {
	    feideLogoutPath = param;
	  }
  }

  @Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String servletPath = req.getServletPath();
		if (servletPath.equals(this.feideLoginPath)) {
			handleLogin(req, resp);
		
		} else if (servletPath.equals(this.feideLogoutPath)) {
			handleLogout(req, resp);
		
		} else { 
		  log.warn("FeideAuthenticator.service: Called by unknown servlet path: "+servletPath);
		}
	}

	private void handleLogin(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
		log.debug("FeideAuthenticator.handleLogin: called");

		try {
			feideHandler.handleLogin(req, resp);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}

	private void handleLogout(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("FeideAuthenticator.handleLogout: called");
		HttpSession session = req.getSession(false);

		WebFeideHandler fh = null;
		if (session != null)
			fh = (WebFeideHandler)session.getAttribute(FeideHandler.class.getName());
		
		if (fh == null) {
			log.debug("FeideAuthenticator.handleLogout: logout called on not logged in session");
			log.debug("Redirecting to "+req.getContextPath());
			resp.sendRedirect(req.getContextPath());
			return;
		}

		try {
			feideHandler.handleLogout(req, resp);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}
}
