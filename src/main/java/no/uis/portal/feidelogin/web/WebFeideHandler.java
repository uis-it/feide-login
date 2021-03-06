/**
 * Copyright University of Stavanger 2010-
 * $Id:$
 */
package no.uis.portal.feidelogin.web;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import no.uis.portal.feidelogin.FeideHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class WebFeideHandler extends FeideHandler {
	
	private static Properties props = new Properties();
	
//	static {
//		// Hardcoded default values - enter your own in a properties file and point to it
//		// with init parameter "settingsFile" in the deployment descriptor
//		props.put("no.uis.feide.metadata-url", "https://lportal-test.uis.no/simplesaml/saml2/idp/metadata.php");
//		props.put("no.uis.feide.issuer-name", "urn:mace:feide.no:services:no.uis.wsapps-test01");
//		props.put("no.uis.feide.sso.relay-state", "https://wsapps-test01.uis.no/medikamentregning/feidelogin");
//		props.put("no.uis.feide.slo.relay-state", "https://wsapps-test01.uis.no/medikamentregning/feidelogout");
//		props.put("no.uis.feide.idp.logout", "https://lportal-test.uis.no/simplesaml/saml2/idp/initSLO.php");
//	}
	
	private static Log log = LogFactory.getLog(WebFeideHandler.class);

	public WebFeideHandler(ServletContext context) {
	  initialize(context);
	}

	public void handleLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		if (isSAMLResponse(request)) {
			// Login response
			Map<String,List<String>> attrs = handleLoginResponse(request, response);

			if (!attrs.containsKey(Constants.FEIDE_USER_ID_ATTRIBUTE)) {
				logError("invalid login response, no "+Constants.FEIDE_USER_ID_ATTRIBUTE+" returned");
				return;
			}
			
			String userId = attrs.get(Constants.FEIDE_USER_ID_ATTRIBUTE).get(0);

      if (userId != null) {
        request.getSession().setAttribute(FeideHandler.class.getName(), this);
        request.getSession().setAttribute(Constants.USER_ID_ATTRIBUTE, userId);
        log.info("FeideAuthenticator.handleLogin: Logged in as "+userId);
        request.getSession().setAttribute(Constants.FEIDE_ATTRIBUTES, attrs);
      }
			
			logInfo("handleLoginResponse returned "+attrs);
			String url = (String) request.getSession().getAttribute("originalRequest");
			if (url == null) {
				logWarn("Login successful, but don't know where to redirect - defaulting to context path");
				// Go to root
				url = request.getContextPath();
			}
			logInfo("Successful login, redirecting user back to "+url);
			response.sendRedirect(url);
		} else {
			// Login request
			sendLoginRequest(request, response);
		}
	}

	
	@Override
  protected void initialize(ServletContext context) {
	  loadProperties(context);
    super.initialize(context);
  }

  private void loadProperties(ServletContext context) {
		String settingsFile = context.getInitParameter("FEIDEsettingsFile");
		if (settingsFile == null) {
			logInfo("No settingsFile init parameter found, proceeding with default settings");
			return;
		}
		InputStream settingsStream = null;
		try {
			settingsStream = context.getResourceAsStream(settingsFile);
			if (settingsStream == null) {
			  settingsStream = new FileInputStream(settingsFile);
			}
      props.load(settingsStream);
			logInfo("Settings loaded from "+settingsFile);
		} catch (Exception e) {
			logError("Could not load settings from "+settingsFile+": "+e.getMessage());
			throw new IllegalArgumentException(e);
		} finally {
		  if (settingsStream != null) {
		    try {
          settingsStream.close();
        } catch(IOException e) {
          logWarn(e);
        }
		  }
		}
		
	}

	public void handleLogout(HttpServletRequest request, HttpServletResponse response) throws Exception {
		if (isSAMLRequest(request)) {
			logDebug("Received SAML2 logout request, handling that");
			handleLogoutRequest(request, response);
		} else if (isSAMLResponse(request)) {
			logDebug("Received SAML2 logout response, redirecting to "+request.getContextPath());
			response.sendRedirect(request.getContextPath());
		} else {
			logDebug("Logout requested, redirecting to iDP");
			logDebug("parameters: "+request.getParameterMap());
			initLogoutRequest(request, response);
		}
	}
		
	protected void sendLoginRequest(HttpServletRequest req, HttpServletResponse resp) throws Exception {
		String redirectUrl = createSSORedirectRequestUrl(resp);
		addNoCacheHeaders(resp);
		logInfo("redirecting to "+redirectUrl);
		resp.sendRedirect(redirectUrl);
	}


	protected void localLogout(HttpServletRequest request, HttpServletResponse response) {
		String userId = (String) request.getSession().getAttribute(Constants.USER_ID_ATTRIBUTE);
		logDebug("logging out user "+userId);
		request.getSession().setAttribute(Constants.USER_ID_ATTRIBUTE, null);
	}


	protected void logError(Object o) {
		log.error(o);
	}

	protected void logWarn(Object o) {
		log.warn(o);
	}

	protected void logInfo(Object o) {
		log.info(o);
	}

	protected void logDebug(Object o) {
		log.debug(o);
	}

	protected String getProperty(String name)  {
		return props.getProperty(name);
	}

}
