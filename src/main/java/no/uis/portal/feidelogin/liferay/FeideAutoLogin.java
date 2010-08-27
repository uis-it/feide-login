package no.uis.portal.feidelogin.liferay;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.uis.portal.feidelogin.liferay.LiferayFeideHandler;



import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.security.auth.AutoLoginException;

/**
 * This AutoLogin handles conversation with the FEIDE idp and uses the emailAddress attribute 
 * to fetch the authenticated user.
 * 
 * @author Martin Goldhahn (2904630)
 */
public class FeideAutoLogin implements AutoLogin {


  @Override
  public String[] login(HttpServletRequest request, HttpServletResponse response) throws AutoLoginException {

    if (LiferayFeideHandler.isFeideLoginRequest(request)) {
      try {
        LiferayFeideHandler fh = LiferayFeideHandler.getInstance();
        String[] credentials = fh.handleLogin(request, response);
        if (credentials != null) {
          request.getSession().setAttribute(LiferayFeideHandler.class.getName(), fh);
        }
        return credentials;
      } catch(Exception e) {
        throw new AutoLoginException(e);
      }
    }
    return null;
  }

}
