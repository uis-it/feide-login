/*
 * Copyright (C) 2007 National Association of REALTORS(R)
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished
 * to do so, provided that the above copyright notice(s) and this
 * permission notice appear in all copies of the Software and that
 * both the above copyright notice(s) and this permission notice
 * appear in supporting documentation.
 */

/*
 * MetaDataCache.java
 *
 * Created on August 4, 2007, 2:30 PM
 *
 */

package net.clareitysecurity.websso.metadata;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.KeyDescriptorImpl;
import org.opensaml.saml2.metadata.provider.FileBackedHTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;

/**
 * MetaDataCache is the organizer bucket class for handling SAML 2.0 metadata. It
 * is used to read metadata and cache it for later use.
 *
 * @author Paul Hethmon (original author)
 * @author Martin Goldhahn (2904630)
 */
public class MetaDataCache {
  private String metaUrl;
  private String metaFile;
  private BasicParserPool parser;
  private int metaTimeout;
  private PublicKey publicKey;
  private SignatureValidator signatureValidator;

  private Map<String, SingleLogoutService> sloServiceMap = new HashMap<String, SingleLogoutService>();

  private Map<String, SingleSignOnService> ssoServiceMap;

  /**
   * Set the URL to retrieve the metadata from.
   * @param newMetaUrl The URL to the metadata XML file.
   */
  public void setMetaUrl(String newMetaUrl) {
    metaUrl = newMetaUrl;
  }
  /**
   * Get the URL of the metadata XML file.
   * @return The metadata XML file URL.
   */
  public String getMetaUrl() {
    return metaUrl;
  }
  /**
   * Set the location of the local backing file for the metadata. This
   * file will be created if it does not exist.
   * @param newMetaFile The full filename to use for the metadata backing file.
   */
  public void setMetaFile(String newMetaFile) {
    metaFile = newMetaFile;
  }
  /**
   * Get the full filename of the local metadata backing file.
   * @return The full filename of the metadata backing file.
   */
  public String getMetaFile() {
    return metaFile;
  }
  /**
   * Set the time in milliseconds to wait for the metadata server to respond
   * before timing out.
   * @param newTimeOut The time in milliseconds to wait for the server to respond.
   */
  public void setMetaTimeout(int newMetaTimeout) {
    metaTimeout = newMetaTimeout;
  }
  /**
   * Get the time in milliseconds to wait for the metadata server to respond.
   * @return The timeout period in milliseconds.
   */
  public int getMetaTimeout() {
    return metaTimeout;
  }
  /**
   * Set the value of the PublicKey used to verify signatures of an IdP.
   * @param newPublicKey The PublicKey object.
   */
  public void setPublicKey(PublicKey newPublicKey) {
    publicKey = newPublicKey;
  }
  /**
   * Get the PublicKey used to verify signatures of an IdP.
   * @return The PublicKey
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }
  /**
   * Set the SignatureValidator object value. The SignatureValidator is used to
   * validate the signatures of signed SAML objects from the IdP.
   * @param newSignatureValidator The new SignatureValidator object.
   */
  public void setSignatureValidator(SignatureValidator newSignatureValidator) {
    signatureValidator = newSignatureValidator;
  }
  /**
   * Get the SignatureValidator object to validate signatures of the IdP.
   * @return The SignatureValidator object.
   */
  public SignatureValidator getSignatureValidator() {
    return signatureValidator;
  }
  
  /** Creates a new instance of MetaDataCache */
  public MetaDataCache() throws org.opensaml.xml.ConfigurationException {
    // Create a parser pool for later use
    parser = new BasicParserPool();
    // Choose to use the Bouncy Castle JCE provider most often
    Security.insertProviderAt(new BouncyCastleProvider(), 2);
    // Provide some default values
    setMetaTimeout(60000);
    setMetaFile("metadata-backing-file.xml");
    setMetaUrl("http://127.0.0.1/metadata.xml");
}
 
  /**
   * Fetch the metadata from the metadata server as provided in @see #setMetaUrl(String) method. You must
   * also set the @see #setMetaFile(String) backing file and the @see #setMetaTimeout timeout values before
   * calling this method.
   */
  public boolean fetchMetaData() 
    throws MetadataProviderException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException,
      java.security.spec.InvalidKeySpecException
  {
    // Pull the metadata from the web server
    FileBackedHTTPMetadataProvider fbmd;
    fbmd = new FileBackedHTTPMetadataProvider(getMetaUrl(), getMetaTimeout(), getMetaFile());
    fbmd.setParserPool(parser);
    
    fbmd.initialize();
    
    // Now start to parse it out.
    EntityDescriptorImpl exml;
    exml = (EntityDescriptorImpl) fbmd.getMetadata();
//    System.out.println("Have EntityDescriptorImpl XMLObject");
    
    IDPSSODescriptorImpl idp;
    idp = (IDPSSODescriptorImpl) exml.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
//    System.out.println("Got IDPSSODescriptor");
    
    java.util.List<KeyDescriptor> keyList;
    keyList = idp.getKeyDescriptors();
    
    KeyDescriptorImpl keyDesc;
    keyDesc = (KeyDescriptorImpl) keyList.get(0);
    
    // Get the KeyInfo node
    KeyInfo keyInfo;
    keyInfo = keyDesc.getKeyInfo();
//    System.out.println("Got KeyInfo");

    // Get the list of certificates
    java.util.List<X509Data> x509List;
    x509List = keyInfo.getX509Datas();
    
    // Pull out the first x509 data element
    X509Data x509Data;
    x509Data = x509List.get(0);
    
    // Now the certificates
    java.util.List<X509Certificate> x509CertList;
    x509CertList = x509Data.getX509Certificates();
    
    // finally the certificate
    X509Certificate x509Cert;
    x509Cert = x509CertList.get(0);

    // We need a Java X509Certificate object first
    java.security.cert.X509Certificate jX509Cert;
    // Now create it based on the OpenSAML X509Certificate object
    jX509Cert = KeyInfoHelper.getCertificate(x509Cert);
    // Now we can pull out the public key part of the certificate into a KeySpec
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( jX509Cert.getPublicKey().getEncoded() );
    
    // Get our KeyFactory object that creates key objects for us specifying RSA
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//    System.out.println("provider = " + keyFactory.getProvider().toString() );
    // Now let's finally generate that PublicKey that we can actually use to validate signatures
    setPublicKey(keyFactory.generatePublic(pubKeySpec));
    
    // Now we need to validate the signature. First create the Credentials
    org.opensaml.xml.security.x509.BasicX509Credential publicCredential = new org.opensaml.xml.security.x509.BasicX509Credential();
    
    // Add the PublicKey value
    publicCredential.setPublicKey(getPublicKey());
    
    // And create a SignatureValidator with it.
    setSignatureValidator( new org.opensaml.xml.signature.SignatureValidator(publicCredential) );
    
    // get the single logout Services
    List<SingleLogoutService> sloServices = idp.getSingleLogoutServices();
    Map<String, SingleLogoutService> sloMap = new HashMap<String, SingleLogoutService>();
    for (SingleLogoutService sloService : sloServices) {
      sloMap.put(sloService.getBinding(), sloService);
    }
    setSloServiceMap(sloMap);
    
    // get the single sign on Services
    List<SingleSignOnService> ssoServices = idp.getSingleSignOnServices();
    Map<String, SingleSignOnService> ssoMap = new HashMap<String, SingleSignOnService>();
    for (SingleSignOnService ssoService : ssoServices) {
      ssoMap.put(ssoService.getBinding(), ssoService);
    }
    setSsoServiceMap(ssoMap);
    return true;
  }
  
  private void setSsoServiceMap(Map<String, SingleSignOnService> ssoMap) {
    this.ssoServiceMap = ssoMap;
    
  }
  
  private void setSloServiceMap(Map<String, SingleLogoutService> sloMap) {
    this.sloServiceMap = sloMap;
  }
  
  /**
   * @return Single Logout Services indexed on binding.
   */
  public Map<String, SingleLogoutService> getSloServiceMap() {
    return sloServiceMap;
  }

  /**
   * @return Single Sign On Services indexed on binding
   */
  public Map<String, SingleSignOnService> getSsoServiceMap() {
    return ssoServiceMap;
  }
}
