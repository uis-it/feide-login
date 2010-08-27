package no.uis.portal.feidelogin;

import java.io.File;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.clareitysecurity.websso.metadata.MetaDataCache;

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.util.URLBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public abstract class FeideHandler {

	protected MetaDataCache metadata;
	protected String idpSsoUrl;
	protected String idpSloUrl;
	protected String issuerName;
	protected String ssoRelayState;
	protected String sloRelayState;
	protected static volatile String loginUri;
	public static final String PROTOCOL_HTTPS = "https";
	protected static final String NO_UIS_FEIDE_METADATA_URL = "no.uis.feide.metadata-url";
//	public static final String REQ_PARAM_FEIDE_UID = "no.uis.feide.uid";

	public FeideHandler() {
	}

	protected  void initialize() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logError(e);
		}
		try {

			String metadataUrl = getProperty(NO_UIS_FEIDE_METADATA_URL);
			if (metadataUrl == null) {
				logError("property '" + NO_UIS_FEIDE_METADATA_URL + "' is not set");
				return;
			}
			this.metadata = updateMetaData(metadataUrl);
			idpSsoUrl = metadata.getSsoServiceMap().get(SAMLConstants.SAML2_REDIRECT_BINDING_URI).getLocation();
			issuerName = getProperty("no.uis.feide.issuer-name");
			ssoRelayState = getProperty("no.uis.feide.sso.relay-state");
			sloRelayState = getProperty("no.uis.feide.slo.relay-state");
			idpSloUrl = getProperty("no.uis.feide.idp.logout");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}


	protected abstract void sendLoginRequest(HttpServletRequest req, HttpServletResponse resp) throws Exception;

	protected abstract void localLogout(HttpServletRequest request, HttpServletResponse response);

	public boolean isSAMLRequest(HttpServletRequest req) {
		String samlParam = req.getParameter("SAMLRequest");
		return samlParam != null;
	}

	public boolean isSAMLResponse(HttpServletRequest req) {
		String samlParam = req.getParameter("SAMLResponse");
		return samlParam != null;
	}

	protected abstract void logError(Object o);
	protected abstract void logWarn(Object o);
	protected abstract void logDebug(Object o);

	protected void addNoCacheHeaders(HttpServletResponse resp) {
		// set encoding and cache control for response
		resp.setCharacterEncoding("UTF-8");
		resp.addHeader("Cache-control", "no-cache, nostore");
		resp.addHeader("Pragma", "no-cache");
	}

	/**
	 * Deflate and base64-encode the input string.
	 * @see {@link <a href="http://www.ietf.org/rfc/rfc1951.txt">RFC1951</a>}
	 */
	protected String encodeString(String input) {
		byte[] output = new byte[input.length()];

		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		deflater.setInput(input.getBytes());
		deflater.finish();
		int outputLength = deflater.deflate(output);
		return Base64.encodeBytes(output, 0, outputLength);
	}

	protected String convertToQueryParameter(XMLObject authRequest)
	throws MarshallingException {
		// The object needs to be converted to a XML string
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authRequest);
		Element authRequestElement = marshaller.marshall(authRequest);
		StringWriter sw = new StringWriter();
		XMLHelper.writeNode(authRequestElement, sw);
		String requestString = sw.toString();

		// Now we need to base64 encode the message
		String authRequestEncoded = encodeString(requestString);
		return authRequestEncoded;
	}

	protected String createMessageId() {
		return "uis_" + new DateTime().getMillis();
	}

	protected String createSSORedirectRequestUrl(HttpServletResponse resp) throws Exception {
		//    RedirectHandler handler = new RedirectHandler();
		//
		//    handler.setActionURL(idpSsoUrl);
		//    handler.setIssuerName(issuerName);
		//    handler.setProviderName(providerName);
		//    handler.setRelayState(ssoRelayState);
		//
		//    String redirectURL = handler.createSAMLRedirectAttribute(resp);
		//    return redirectURL;

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		AuthnRequestBuilder authReqBuilder = (AuthnRequestBuilder)builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		IssuerBuilder issueBuilder = (IssuerBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

		AuthnRequest authRequest = authReqBuilder.buildObject();
		Issuer issuer = issueBuilder.buildObject();
		issuer.setValue(issuerName);
		authRequest.setIssuer(issuer);
		authRequest.setDestination(idpSsoUrl);
		authRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		authRequest.setVersion(SAMLVersion.VERSION_20);
		authRequest.setIssueInstant(new DateTime());
		authRequest.setID(createMessageId());

		String authRequestEncoded = convertToQueryParameter(authRequest);

		URLBuilder urlBuilder = new URLBuilder(idpSsoUrl);
		List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();

		// clear any query parameters that might exist in the SSO URL
		queryParams.clear();

		queryParams.add(new Pair<String, String>("SAMLRequest", authRequestEncoded));
		if (!DatatypeHelper.isEmpty(this.ssoRelayState)) {
			queryParams.add(new Pair<String, String>("RelayState", ssoRelayState));
		}

		return urlBuilder.buildURL();
	}

	protected String createSLORedirectResponseUrl(LogoutRequest sloRequest, HttpServletResponse resp)
	throws Exception {

		XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
		LogoutResponseBuilder sloResponseBuilder = (LogoutResponseBuilder)builderFactory.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		IssuerBuilder issuerBuilder = (IssuerBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		//    NameIDBuilder nameIdBuilder = (NameIDBuilder)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		//    SignatureBuilder sigBuilder = (SignatureBuilder)builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
		StatusBuilder statusBuilder = (StatusBuilder)builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder)builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME); 

		LogoutResponse sloResponse = sloResponseBuilder.buildObject();

		// response attributes
		sloResponse.setVersion(SAMLVersion.VERSION_20);
		sloResponse.setID(createMessageId());
		sloResponse.setInResponseTo(sloRequest.getID());
		sloResponse.setIssueInstant(new DateTime());
		String destination = metadata.getSloServiceMap().get(SAMLConstants.SAML2_REDIRECT_BINDING_URI).getLocation();
		sloResponse.setDestination(destination);

		// issuer
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(this.issuerName);
		sloResponse.setIssuer(issuer);

		// signature
		// TODO signature for SLO response

		// There is no setter for nameId on response
		//    NameID nameId = nameIdBuilder.buildObject();
		//    nameId.setValue(sloRequest.getMessage().getNameID().getValue());
		//    sloResponse.set

		Status status = statusBuilder.buildObject();
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);
		status.setStatusCode(statusCode);
		sloResponse.setStatus(status);

		String samlResponseParam = convertToQueryParameter(sloResponse);

		URLBuilder urlBuilder = new URLBuilder(destination);
		List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
		queryParams.clear();

		queryParams.add(new Pair<String, String>("SAMLResponse", samlResponseParam));
		queryParams.add(new Pair<String, String>("RelayState", sloRelayState));

		return urlBuilder.buildURL();
	}

	public void handleLogoutRequest(HttpServletRequest req, HttpServletResponse resp)
	throws Exception {

		boolean needLocalLogout = false;
		HttpSession session = req.getSession(false);
		if (session != null) {
			FeideHandler fhSession = (FeideHandler)session.getAttribute(FeideHandler.class.getName());
			if (fhSession != null) {
				needLocalLogout = true;
				session.setAttribute(FeideHandler.class.getName(), null);
			}
		}
 
		if (needLocalLogout) {
			localLogout(req, resp);
		}
		LogoutRequestReceiver sloRequest = new LogoutRequestReceiver();

		sloRequest.setSignatureValidator(metadata.getSignatureValidator());

		sloRequest.processRequest(req);

		String redirectUrl = createSLORedirectResponseUrl(sloRequest.getMessage(), resp);
		addNoCacheHeaders(resp);
		logDebug("handleLogoutRequest: redirecting to "+redirectUrl);
		resp.sendRedirect(redirectUrl);

	}

	public void initLogoutRequest(HttpServletRequest req, HttpServletResponse resp) throws Exception {
		URLBuilder urlBuilder = new URLBuilder(idpSloUrl);

		List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<String, String>("RelayState", sloRelayState));

		String redirectURL = urlBuilder.buildURL();
		logDebug("initLogoutRequest: redirecting to "+redirectURL);
		resp.sendRedirect(redirectURL);
	}

	protected MetaDataCache updateMetaData(String metadataUrl) throws Exception {

		MetaDataCache md = new MetaDataCache();

		// accept self-signed certificates
		Protocol protocol = new Protocol(PROTOCOL_HTTPS, (ProtocolSocketFactory)new EasySSLProtocolSocketFactory(), 443);
		Protocol.registerProtocol(PROTOCOL_HTTPS, protocol);

		md.setMetaUrl(metadataUrl);
		String metaFilePath = new File(System.getProperty("java.io.tmpdir"), "metadata-backing-feide.xml").getAbsolutePath();
		md.setMetaFile(metaFilePath);

		md.fetchMetaData();

		return md;
	}

	protected Map<String,List<String>> handleLoginResponse(HttpServletRequest req, HttpServletResponse resp)
	throws Exception {
		LoginResponseReceiver samlResp = new LoginResponseReceiver();
		samlResp.setSignatureValidator(metadata.getSignatureValidator());
		samlResp.processRequest(req);

		return samlResp.getAttributeValues();
	}

	protected abstract String getProperty(String name);

}