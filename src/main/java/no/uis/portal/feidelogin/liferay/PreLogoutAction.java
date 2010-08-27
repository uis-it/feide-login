package no.uis.portal.feidelogin.liferay;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import no.uis.portal.feidelogin.FeideHandler;

import com.liferay.portal.kernel.events.Action;
import com.liferay.portal.kernel.events.ActionException;

/**
 * This class initiates a logout request from the IDP by calling initSLO.php.
 * 
 * @author Martin Goldhahn 2904630
 *
 */
public class PreLogoutAction extends Action {

  @Override
  public void run(HttpServletRequest request, HttpServletResponse response) throws ActionException {
    
    HttpSession session = request.getSession(false);
    if (session == null) {
      return;
    }
    
    FeideHandler fh = (FeideHandler)session.getAttribute(LiferayFeideHandler.class.getName());
    if (fh != null) {
      try {
        fh.initLogoutRequest(request, response);
      } catch(Exception e) {
        throw new ActionException(e);
      }
    }
  }

}
