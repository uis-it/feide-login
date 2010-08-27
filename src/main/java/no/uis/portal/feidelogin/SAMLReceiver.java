package no.uis.portal.feidelogin;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.BaseSAML2MessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.ws.message.MessageException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.Validator;

public abstract class SAMLReceiver<MessageType extends SignableSAMLObject> {

  private SignatureValidator signatureValidator;
  private MessageType message;
  private ParserPool parser = new BasicParserPool();
  
  public SAMLReceiver(){
  }
  
  public void setSignatureValidator(SignatureValidator signatureValidator) {
    this.signatureValidator = signatureValidator;
  }

  public SignatureValidator getSignatureValidator() {
    return signatureValidator;
  }

  public void processRequest(HttpServletRequest httpReq) throws Exception {
    
    HttpServletRequestAdapter reqAdapter = new HttpServletRequestAdapter(httpReq);
    
    BasicSAMLMessageContext<MessageType,?,?> context = new BasicSAMLMessageContext<MessageType, SAMLObject, SAMLObject>();
    context.setInboundMessageTransport(reqAdapter);
    
    BaseSAML2MessageDecoder decoder;
    String httpMethod = reqAdapter.getHTTPMethod();
    if (httpMethod.equals("POST")) {
      decoder = new HTTPPostDecoder(parser);
    } else if (httpMethod.equals("GET")) {
      decoder = new HTTPRedirectDeflateDecoder(parser);
    } else {
      throw new MessageException("unknown method: " + httpMethod);
    }

    decoder.decode(context);
    
    @SuppressWarnings("unchecked")
    MessageType message = (MessageType)context.getInboundMessage();
    
    setMessage(message);

    Validator<Signature> sigValidator = getSignatureValidator();
    if (message.isSigned() && sigValidator != null) {
      sigValidator.validate(message.getSignature());
    }

    processInboudMessage(message);
  }

  private void setMessage(MessageType message) {
    this.message = message;
  }

  public MessageType getMessage() {
    return message;
  }

  protected abstract void processInboudMessage(MessageType message) throws Exception;
  
}
