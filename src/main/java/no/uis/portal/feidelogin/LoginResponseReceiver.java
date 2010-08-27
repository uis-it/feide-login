package no.uis.portal.feidelogin;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.signature.SignatureValidator;

public class LoginResponseReceiver extends SAMLReceiver<Response> {

  private Map<String, List<String>> attributeValues = Collections.emptyMap();
  private String login;
  
  public LoginResponseReceiver() throws ConfigurationException {
    super();
  }

  @Override
  protected void processInboudMessage(Response message) throws Exception {
    List<Assertion> assertionList = message.getAssertions();
    
    // We handle only the first assertion, otherwise we would need to deal with several logins
    if (!assertionList.isEmpty()) { 
      SignatureValidator signatureValidator = getSignatureValidator();
      Map<String, List<String>> attribMap = new HashMap<String, List<String>>();
      Assertion assertion = assertionList.get(0);
      if (signatureValidator != null) {
        signatureValidator.validate(assertion.getSignature());
      }
      setLogin(assertion.getSubject().getNameID().getValue());

      addToAttributeMap(attribMap, assertion.getAttributeStatements());
      setAttributeValues(attribMap);
    }
  }

  public synchronized void setLogin(String value) {
    this.login = value;
  }

  public synchronized String getLogin() {
    return login;
  }

  private void addToAttributeMap(Map<String, List<String>> attribMap, List<AttributeStatement> attributeStatements) {
    
    for (AttributeStatement attributeStatement : attributeStatements) {
      for (Attribute attrib : attributeStatement.getAttributes()) {
        String attribName = attrib.getName();

        List<String> values = attribMap.get(attribName);
        if (values == null) {
          values = new LinkedList<String>();
          attribMap.put(attribName, values);
        }
        for (XMLObject val : attrib.getAttributeValues()) {
          String valString;
          if (val instanceof XSString) {
            valString = ((XSString)val).getValue();
          } else {
            valString = String.valueOf(val);
          }
          values.add(valString);
        }
      }
    }
  }

  private synchronized void setAttributeValues(Map<String, List<String>> attributeValues) {
    this.attributeValues = attributeValues;
  }

  public synchronized Map<String, List<String>> getAttributeValues() {
    return attributeValues;
  }
}
