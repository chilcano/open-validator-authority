/*
* Copyright (C) 2006 netfocus S.L.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 2 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program; if not, write to the Free Software Foundation, Inc., 59 Temple
* Place, Suite 330, Boston, MA 02111-1307 USA
*/
package pkiva.logic.services;

//import pkiva.ValidationConstants;
import java.rmi.*;
import java.util.*;
import javax.ejb.*;
import java.security.cert.*;
import pkiva.exceptions.*;
import pkiva.services.*;
import pkiva.validation.*;
import java.security.*;
import java.io.ByteArrayInputStream;
import org.bouncycastle.jce.PKCS7SignedData;
import pkiva.exceptions.*;
import pkiva.*;
import org.bouncycastle.asn1.*;

/** This class allows access to some Certificate operations */
public class CertificateBean implements SessionBean {
    private SessionContext context;
    
    /** Gets a field from a certificate
     * @param certificate Certificate to get info from.
     * @param dataItem String representing the certificate path.
     * @throws CertificateException If certificate error occurs.
     * @return The object retrieved from certificate, or null if nothing appropiate is found.
     * @see pkiva.parsing.Certificate
     */
    public Object getData(X509Certificate certificate,String dataItem) throws  CertificateException {
        try {
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.getData(). Parameters: certificate=" + (certificate) + ", dataItem=" + dataItem);
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.CertificateParserHome home = (pkiva.logic.CertificateParserHome)svcLoc.getHome("CertificateParser",pkiva.logic.CertificateParserHome.class);
            pkiva.logic.CertificateParser cp = home.create();
            // Changes auditing Aug-04
            //pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Get field '"+dataItem+"' from Certificate SN = "+certificate.getSerialNumber());
            return cp.getData(certificate,dataItem);
        }
        catch(CertificateException ce){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().CertificateException" , ce );
            throw ce;
        }
        catch(Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().Exception " , e );
            throw new CertificateException("Could not find Certificate Parser service");
        }
    }
    
    /** Gets a field from a certificate
     * @param certificate Certificate to get info from.
     * @param dataItem String representing the certificate path.
     * @throws CertificateException If certificate error occurs.
     * @return The object retrieved from certificate, or null if nothing appropiate is found.
     */
    public Object getData(byte[] certificate, String dataItem) throws CertificateException{
        try {
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.getData(). Parameters: certificate=" + (certificate) + ", dataItem=" + dataItem);
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.CertificateParserHome home = (pkiva.logic.CertificateParserHome)svcLoc.getHome("CertificateParser",pkiva.logic.CertificateParserHome.class);
            pkiva.logic.CertificateParser cp = home.create();
            // Changes auditing Aug-04
            //pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Get field '"+dataItem+"' from Certificate as byte[].");
            return cp.getData(certificate,dataItem);
        }
        catch(CertificateException ce){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().CertificateException" , ce );
            throw ce;
        }
        catch(Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().Exception " , e );
            throw  new CertificateException("Could not find Certificate Parser service");
        }
    }
    
    /** Gets a field from a certificate
     * @param certificate Certificate to get info from.
     * @param dataItem String representing the certificate path.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return The object retrieved from certificate, or null if nothing appropiate is found.
     */
    /*public Object getData(DERObject certificate, String dataItem) throws RemoteException,CertificateException{
        try {
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.getData(). Parameters: certificate=" + (certificate) + ", dataItem=" + dataItem);
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.CertificateParserHome home = (pkiva.logic.CertificateParserHome)svcLoc.getHome("CertificateParser",pkiva.logic.CertificateParserHome.class);
            pkiva.logic.CertificateParser cp = home.create();
            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Get field '"+dataItem+"' from Certificate as DERObject.");
            return cp.getData(certificate,dataItem);
        }
        catch(RemoteException rex) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().RemoteException" , rex );
            throw rex;
        }
        catch(CertificateException ce){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().CertificateException" , ce );
            throw ce;
        }
        catch(Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.getData().Exception" , e );
            throw  new CertificateException("Could not find Certificate Parser service");
        }
    }*/
    
    /** Checks certificate validity.
     * @param certificate Certificate to validate
     * @param channel Validation channel to use.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(X509Certificate certificate /*, short channel*/) throws RemoteException, CertificateException {
//        try {
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: cert=" + (certificate!=null?certificate.getSubjectDN():null) /*+ ", channel=" + channel*/);
//            
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            
//            short s=cv.checkValidity(certificate/*,channel*/);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Certificate SN="+certificate.getSerialNumber()+" validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("Certificate SN="+certificate.getSerialNumber()+" validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param certificate Certificate to validate
     * @param channel Validation channel to use.
     * @param policies Set of policies (in String oid form) that the certificate must support
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(X509Certificate certificate /*, short channel*/, Set policies) throws RemoteException, CertificateException {
//        try {
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: cert=" + (certificate!=null?certificate.getSubjectDN():null) /*+ ", channel=" + channel*/);
//            
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            
//            short s=cv.checkValidity(certificate/*,channel*/,policies);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Certificate SN="+certificate.getSerialNumber()+" validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("Certificate SN="+certificate.getSerialNumber()+" validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param certChain Certificate chain to validate
     * @param channel Validation channel to use.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(X509Certificate[] certChain/*, short channel*/) throws RemoteException,CertificateException {
//        try {
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: certChain=" + certChain /*+ ", channel=" + channel*/);
//            
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            
//            short s=cv.checkValidity(certChain/*,channel*/);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Certificate chain validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("Certificate chain validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param certChain Certificate chain to validate
     * @param channel Validation channel to use.
     * @param policies Set of policies (in String oid form) that the certificate must support
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(X509Certificate[] certChain/*, short channel*/, Set policies) throws RemoteException,CertificateException {
//        try {
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: certChain=" + certChain /*+ ", channel=" + channel*/);
//            
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            
//            short s=cv.checkValidity(certChain/*,channel*/,policies);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Certificate chain validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("Certificate chain validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e) {
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param pkcs7 PKCS#7 where to get the certificate chain to validate
     * @param channel Validation channel to use.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(byte[] pkcs7/*, short channel*/) throws RemoteException,CertificateException {
//        try{
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: pkcs7=" + pkcs7 /*+ ", channel=" + channel*/);
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            short s=cv.checkValidity(pkcs7/*,channel*/);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("PKCS#7 validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("PKCS#7 validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param pkcs7 PKCS#7 where to get the certificate chain to validate
     * @param channel Validation channel to use.
     * @param policies Set of policies (in String oid form) that the certificate must support
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return true if the certificate is Valid, false otherwise
     */
//    protected boolean isValid(byte[] pkcs7/*, short channel*/, Set policies) throws RemoteException,CertificateException {
//        try{
//            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: pkcs7=" + pkcs7 /*+ ", channel=" + channel*/);
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = home.create();
//            
//            short s=cv.checkValidity(pkcs7/*,channel*/,policies);
//            pkiva.log.AuditManager.getAuditer(this.getClass()).audit("PKCS#7 validated with result "+ValidationConstants.getConstantDescription(s));
//            pkiva.log.LogManager.getLogger(this.getClass()).info("PKCS#7 validated with result "+ValidationConstants.getConstantDescription(s));
//            return s==ValidationConstants.GOOD;
//        }
//        catch(RemoteException rex){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().RemoteException " , rex );
//            throw rex;
//        }
//        catch(Exception e){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
//            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
//        }
//    }
    
    /** Checks certificate validity.
     * @param request Certificate validation request information (certificate and parameters)
     * @return CertValidationResponse object with validation information
     */
    /* Nuevo metodo de validation
     *  Recibe un objeto CertValidationRequest y llama al EJB de la logic layer
     */
    public CertValidationResponse isValid ( CertValidationRequest request )
    {
      long time = System.currentTimeMillis();
      try
      {
        // TODO: log parameters ( CertValidationRequest.toString)
        if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isValid(). Parameters: " + request);
        ServiceLocator svcLoc=ServiceLocator.getInstance();
        pkiva.logic.CertificateValidatorHome home = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
        pkiva.logic.CertificateValidator cv = home.create();

        CertValidationResponse s = cv.checkValidity(request);
//        pkiva.log.AuditManager.getAuditer(this.getClass()).audit("CertValidationRequest validated with result "+ValidationConstants.getConstantDescription(s));

        // Changes auditing Aug-04
        //pkiva.log.AuditManager.getAuditer(this.getClass()).audit("CertValidationRequest validated with result:"+ (s.toAuditString() ) );

//      pkiva.log.LogManager.getLogger(this.getClass()).info("CertValidationRequest validated with result "+ValidationConstants.getConstantDescription(s));
          time = System.currentTimeMillis() - time;
          if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).info(time + " ms :: CertValidationRequest validated with result:"+(s));

        return s;
      }
      catch(Exception e){
          pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isValid().Exception " , e );
          throw  new RuntimeException("Could validate Certificate due to an internal error: ",e);
      }
    }
    
    /**
     * @param certificate
     * @param profileId
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return
     */
    /*
    public boolean isCAAccepted(X509Certificate certificate, String profileId) throws RemoteException,CertificateException {
        try{
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.isCAAccepted(). Parameters: certificate=" + certificate + ", profileId=" + profileId);
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.CAProfileValidatorHome home = (pkiva.logic.CAProfileValidatorHome)svcLoc.getHome("CAProfileValidator",pkiva.logic.CAProfileValidatorHome.class);
            pkiva.logic.CAProfileValidator cv = home.create();
            return cv.isCAAccepted(certificate,profileId);
        }
        catch(RemoteException rex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isCAAccepted().RemoteException " , rex );
            throw rex;
        }
        catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.isCAAccepted().Exception " , e );
            throw  new CertificateException("Could validate Certificate due to an internal error: "+e.getMessage());
        }
    }
    */
    
    /**
     * @param certificate
     * @param profileId
     * @param accepted
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     */
    /*public void setCAAccepted(X509Certificate certificate, String profileId,boolean accepted) throws RemoteException,CertificateException {
        try{
            pkiva.log.LogManager.getLogger(this.getClass()).info("CertificateBean.setCAAccepted(). Parameters: certificate=" + certificate + ", profileId=" + profileId + ", accepted=" + accepted);
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.CAProfileValidatorHome home = (pkiva.logic.CAProfileValidatorHome)svcLoc.getHome("CAProfileValidator",pkiva.logic.CAProfileValidatorHome.class);
            pkiva.logic.CAProfileValidator cv = home.create();
            cv.setCAAccepted(certificate,profileId,accepted);
        }catch(RemoteException rex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.setCAAccepted().RemoteException " , rex );
            throw rex;
        }catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).error("CertificateBean.setCAAccepted().Exception " , e );
            throw  new CertificateException("Could not find CA Profile Validator service");
        }
    }
    */
    
    /** Constructs a new CertificateBean */
    public CertificateBean() {}
    
    /**
     * @throws CreateException
     */
    public void ejbCreate() throws CreateException {}
    
    /**
     * @param theContext
     */
    public void setSessionContext(SessionContext theContext) {
        this.context = theContext;
    }
    
    public void ejbActivate() {}
    
    public void ejbPassivate() {}
    
    public void ejbRemove() {}
}
