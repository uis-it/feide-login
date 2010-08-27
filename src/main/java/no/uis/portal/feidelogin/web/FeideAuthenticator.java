package no.uis.portal.feidelogin.web;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;

import javax.servlet.Servlet;
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

	protected void doPost(HttpServletRequest req,
			HttpServletResponse resp) throws ServletException, IOException {

		log.info("received a POST at "+req.getServletPath());
		doGet(req, resp);
		
	}
	
	protected void doGet(HttpServletRequest req,
			HttpServletResponse resp) throws ServletException, IOException {
		String servletPath = req.getServletPath();
		if (servletPath.equals(Constants.AUTH_LOGIN_SERVLET)) {
			handleLogin(req, resp);
			return;
		}
		
		if (servletPath.equals(Constants.AUTH_LOGOUT_SERVLET)) {
			handleLogout(req, resp);
			return;
		}
		
		log.error("FeideAuthenticator.doGet: Called by unknown servlet path: "+servletPath);
	}

	private void handleLogin(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
		log.debug("FeideAuthenticator.handleLogin: called");

		ClassLoader classLoader = this.getClass().getClassLoader();
		if (classLoader == null) {
			log.debug("could not get application class loader");
		} else {
			log.debug("Classpath:");
			URL[] urls = ((URLClassLoader)classLoader).getURLs();

			for(int i=0; i< urls.length; i++) {
				log.debug(urls[i].getFile());
			}    
			log.debug("(end classpath)");
			
		}
		WebFeideHandler fh = WebFeideHandler.getInstance();
		try {
			String userId = fh.handleLogin(req, resp);
			if (userId != null) {
				req.getSession().setAttribute(FeideHandler.class.getName(), fh);
				req.getSession().setAttribute(Constants.USER_ID_ATTRIBUTE, userId);
				log.info("FeideAuthenticator.handleLogin: Logged in as "+userId);
			}
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
			fh.handleLogout(req, resp);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}
}
