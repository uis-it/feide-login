/**
 * Copyright University of Stavanger 2010-
 * $Id:$
 */
package no.uis.portal.feidelogin.liferay;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.uis.portal.feidelogin.FeideHandler;
import no.uis.portal.feidelogin.liferay.FeideAutoLogin;

import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.servlet.StringServletResponse;
import com.liferay.portal.kernel.util.NullWrapper;
import com.liferay.portal.kernel.util.PortalClassInvoker;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.security.auth.CompanyThreadLocal;
import com.liferay.portal.service.CompanyLocalServiceUtil;
import com.liferay.portal.service.UserLocalServiceUtil;

public class LiferayFeideHandler extends FeideHandler {
	private static Log log = LogFactoryUtil.getLog(FeideAutoLogin.class);

	private static volatile LiferayFeideHandler singleton;

	public static LiferayFeideHandler getInstance() {
		LiferayFeideHandler fh = singleton;
		if (fh == null) {
			synchronized(LiferayFeideHandler.class) {
				fh = singleton;
				if (fh == null) {
					fh = new LiferayFeideHandler();
					fh.initialize(null);
					singleton = fh;
				}
			}
		}
		return fh;
	}

	public static boolean hasInstance() {
		FeideHandler fh = singleton;
		return fh != null;
	}

	private LiferayFeideHandler() {
	}

	/* (non-Javadoc)
	 * @see no.uis.portal.feidelogin.FeideHandler#handleLogin(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public String[] handleLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
		if (isSAMLResponse(request)) {
			Map<String,List<String>> attrs = handleLoginResponse(request, response);
			return findLiferayCredentials(request, response, attrs);
		} else {
			sendLoginRequest(request, response);
		}
		return null;
	}

	protected void sendLoginRequest(HttpServletRequest req, HttpServletResponse resp) throws Exception
	{
		String redirectURL = createSSORedirectRequestUrl(resp);
		addNoCacheHeaders(resp);
		req.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirectURL);
	}


	private String[] findLiferayCredentials(HttpServletRequest req, HttpServletResponse resp, Map<String, List<String>> attribs)
	throws IOException
	{
		try {
			String authType = CompanyLocalServiceUtil.getCompanyById(CompanyThreadLocal.getCompanyId()).getAuthType();
			User user = null;
			if (authType.equals("emailAddress")) {
				List<String> emailAddresses = attribs.get("mail");
				if (emailAddresses != null) {
					for (String emailAddress : emailAddresses) {
						try {
							user = UserLocalServiceUtil.getUserByEmailAddress(CompanyThreadLocal.getCompanyId(), emailAddress);
							break;
						} catch(NoSuchUserException ex) {
							log.info("no user for email found " + emailAddress);
						}
					}
				}
			} else {
				log.error("authtype not supported " + authType);
				return null;
			}
			if (user != null) {
				long userId = user.getUserId();
				String[] credentials =
				{ String.valueOf(userId), user.getPassword(), StringPool.TRUE };
				return credentials;
			}
		} catch(Exception e) {
			log.warn("find user " + e);
		}

		return null;
	}

	protected void localLogout(HttpServletRequest request, HttpServletResponse response) {
		try {
			Object mapping = new NullWrapper("org.apache.struts.action.ActionMapping");
			Object form = new NullWrapper("org.apache.struts.action.ActionForm");
			StringServletResponse stringResp = new StringServletResponse(response);
			Object[] args = new Object[] {mapping, form, request, stringResp};
			// the invocation will trigger a NPE, because the mapper is null, which can be ignored
			PortalClassInvoker.invoke("com.liferay.portal.action.LogoutAction", "execute", args);
			//      String respString = stringResp.getString();
			//      System.out.println(respString);
		} catch (Exception e) {
			log.warn(e);
		}

	}

	private static String getLoginUri() {
		String lu = loginUri;
		if (lu == null) {
			synchronized(LiferayFeideHandler.class) {
				lu = loginUri;
				if (lu == null) {
					try {
						loginUri = lu = PropsUtil.get("no.uis.feide.login-uri");
					} catch(Exception e) {
						log.error(e);
					}
				}
			}
		}
		return lu;
	}

	/**
	 * We use a static method to not have to instantiate the FEIDE handler unnecessarily. 
	 * @param request
	 * @return
	 */
	public static boolean isFeideLoginRequest(HttpServletRequest request) {
		String reqUri = request.getRequestURI();
		return reqUri.startsWith(getLoginUri());
	}

	protected void logError(Object o) {
		log.error(o);
	}

	protected void logWarn(Object o) {
		log.warn(o);
	}

	protected void logDebug(Object o) {
		log.debug(o);
	}

	protected String getProperty(String name)  {
		try {
			return PropsUtil.get(name);
		} catch (Exception e) {
			log.error("Exception getting property: "+e);
			return null;
		}
	}

}
