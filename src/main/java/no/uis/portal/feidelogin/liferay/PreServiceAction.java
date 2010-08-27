package no.uis.portal.feidelogin.liferay;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.uis.portal.feidelogin.FeideHandler;

import com.liferay.portal.kernel.events.Action;
import com.liferay.portal.kernel.events.ActionException;

public class PreServiceAction extends Action {

  /**
   * This handles the LogoutRequest from FEIDE IDP.
   */
  @Override
  public void run(HttpServletRequest request, HttpServletResponse response) throws ActionException {
    if (!LiferayFeideHandler.hasInstance()) {
      return;
    }
    FeideHandler fh = LiferayFeideHandler.getInstance();
    
    String requestURI = request.getRequestURI();
    
    if (fh.isSAMLRequest(request) && requestURI.equals("/c/feide/logout/consumer")) {
      try {
        fh.handleLogoutRequest(request, response);
      } catch(Exception e) {
        throw new ActionException(e);
      }
    }
  }

}
