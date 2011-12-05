package no.uis.portal.feidelogin.web;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FeideFilter implements Filter {

  private static Log log = LogFactory.getLog(FeideFilter.class);
  private String feideLoginPath;
  private String feideLogoutPath;

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain fc) throws IOException,
      ServletException
  {

    log.info("FeideFilter.doFilter: called");
    HttpServletRequest hreq = (HttpServletRequest)servletRequest;
    HttpServletResponse hresp = (HttpServletResponse)servletResponse;

    if (!(authenticated(hreq) || isFeideServletUri(hreq.getServletPath()))) {
      hreq.getSession().setAttribute("originalRequest", hreq.getRequestURL().toString());
      RequestDispatcher dispatcher = hreq.getRequestDispatcher(feideLoginPath);
      dispatcher.forward(hreq, hresp);
      return;
    }

    fc.doFilter(servletRequest, servletResponse);
  }

  private boolean isFeideServletUri(String uri) {
    if (uri.equals(feideLoginPath) || uri.equals(feideLogoutPath)) {
      return true;
    }
    return false;
  }

  private boolean authenticated(HttpServletRequest req) {

    HttpSession session = req.getSession(false);

    if (session == null) {
      return false;
    }

    String userId = (String)session.getAttribute(Constants.USER_ID_ATTRIBUTE);

    if (log.isDebugEnabled()) {
      log.debug("FeideFilter.authenticated: userId=" + userId);
    }
    if (userId == null) {
      return false;
    }

    return true;
  }

  @Override
  public void destroy() {
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    ServletContext servletContext = filterConfig.getServletContext();
    String param = servletContext.getInitParameter(Constants.PARAM_FEIDE_LOGIN_PATH);
    if (param != null) {
      this.feideLoginPath = param;
    } else {
      this.feideLoginPath = Constants.FEIDE_LOGIN_PATH_DEFAULT; 
    }
    param = servletContext.getInitParameter(Constants.PARAM_FEIDE_LOGOUT_PATH);
    if (param != null) {
      this.feideLogoutPath = param;
    } else {
      this.feideLogoutPath = Constants.FEIDE_LOGOUT_PATH_DEFAULT; 
    }
  }

}
