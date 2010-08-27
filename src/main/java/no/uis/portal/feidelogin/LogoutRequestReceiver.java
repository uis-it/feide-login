package no.uis.portal.feidelogin;

import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.xml.ConfigurationException;

public class LogoutRequestReceiver extends SAMLReceiver<LogoutRequest> {

  public LogoutRequestReceiver() throws ConfigurationException {
    super();
  }
  

  @Override
  protected void processInboudMessage(LogoutRequest sloReq) throws Exception {
    sloReq.validate(true);
  }
}
