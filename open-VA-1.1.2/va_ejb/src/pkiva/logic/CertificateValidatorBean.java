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
package pkiva.logic;

import java.security.*;
import java.security.cert.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;

import javax.ejb.*;
import pkiva.services.*;
import java.rmi.*;

import pkiva.parsing.wrappers.*;
import pkiva.exceptions.*;
import pkiva.validation.*;
import pkiva.validation.crl.*;
import pkiva.validation.ocsp.*;
//import pkiva.ValidationConstants;
import pkiva.providers.TimeProvider;
import pkiva.providers.CertStoreProvider;
import pkiva.ldap.*;
import pkiva.log.*;
import pkiva.log.operations.*;
import pkiva.services.*;

import pkiva.providers.jce.PKIVAJCEProvider;
/** Logic layer EJB that validates certificates and certificate chains in various formats */
public class CertificateValidatorBean implements SessionBean {
    private SessionContext context;
    
    /**
     * Checks validity of a Certificate chain.
     */
//    protected short checkValidity(X509Certificate[] chain) throws RemoteException{
//        return checkValidity(chain,Collections.EMPTY_SET);
//    }
    
    /**
     * Checks validity of a Certificate.
     */
//    protected short checkValidity(X509Certificate cert) throws RemoteException{
//        return checkValidity(cert,Collections.EMPTY_SET);
//    }
    
    /**
     * Checks validity of a PKCS#7
     */
//    protected short checkValidity(byte[] pkcs7) throws RemoteException{
//        return checkValidity(pkcs7,Collections.EMPTY_SET);
//    }
    
    /** Checks the validity of a pkcs7
     * @param pkcs7 Byte serialization of pkcs7 to validate.
     * @param vc Validation channel to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
//    protected short checkValidity(byte[] pkcs7, String vc){
//        return checkValidity(pkcs7,vc,Collections.EMPTY_SET);
//    }
    
    /** This method validates the entire certificate chain with the given validation channel.
     * Expects forward order (end entity cert first), and no trust anchor passed (root
     * CA certificate). If there are TrustAnchors inside the array, they are eliminated.
     *
     * Uses the concrete SUNJCE implementation (CertPathValidator) for J2SE 1.4.2,
     * because it's more stable than BC one, and enforces validation of user-based
     * CertPathCheckers
     *
     * In the EJB is only implemented the basic validation, without CRL validation,
     * that is performed in the VCs (implemented with RAs).
     * @param chain Certificate chain to validate
     * @param vc Validation channel to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
//    protected short checkValidity(X509Certificate[] chain, String vc){
//        return checkValidity(chain, vc, Collections.EMPTY_SET);
//    }
    
    /** Checks the validity of an incomplete certificate chain. The certificate chain
     * must be completed with out-of-band repository-based CA-certificates.
     * @param certificate Certificate to validate
     * @param vc Validation channel to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
//    protected short checkValidity(X509Certificate certificate, String vc) {
//        return checkValidity(certificate, vc, Collections.EMPTY_SET);
//    }
    
    /** This method validates the entire certificate chain with the given validation channel.
     * Expects forward order (end entity cert first), and no trust anchor passed (root
     * CA certificate). If there are TrustAnchors inside the array, they are eliminated.
     *
     * Uses the concrete SUNJCE implementation (CertPathValidator) for J2SE 1.4.2,
     * because it's more stable than BC one, and enforces validation of user-based
     * CertPathCheckers
     *
     * In the EJB is only implemented the basic validation, without CRL validation,
     * that is performed in the VCs (implemented with RAs).
     *
     * @param chain Certificate chain to validate
     * @param policies Policies to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
  protected CertValidationResponse checkValidity(X509Certificate[] chain, Set policies, boolean infoRequested, int audit_id) throws RemoteException{
  {
//    short result = ValidationConstants.INTERNAL_SERVER_ERROR;
    CertValidationResponse result = null;
    Throwable lastError = null;
    String vc = null;
    int vcPos = 0;
    HashSet vcUsed = new HashSet();
    do
    {
      if(chain.length == 0)
        vc = null;
      else if(chain.length == 1)
      {//Look for TrustAnchor and use its vc.
          boolean found = false;
          pkiva.log.LogManager.getLogger(this.getClass()).info("************* getIssuerDN" + chain[0].getIssuerDN());
          pkiva.log.LogManager.getLogger(this.getClass()).info("************* getIssuerDN.class" + chain[0].getIssuerDN().getClass());
          for (Iterator it = CertStoreProvider.getTrustAnchors().iterator();it.hasNext();)
          {
              TrustAnchor ta = (TrustAnchor)it.next();
              pkiva.log.LogManager.getLogger(this.getClass()).info("************* ta.getSubjectDN()" + ta.getTrustedCert().getSubjectDN());
              pkiva.log.LogManager.getLogger(this.getClass()).info("************* ta.getSubjectDN().class" + ta.getTrustedCert().getSubjectDN().getClass());
              if(ta.getTrustedCert().getSubjectDN().equals(chain[0].getIssuerDN()))
              {
                  pkiva.log.LogManager.getLogger(this.getClass()).info("checkValidity for ta:" + ta.getTrustedCert());
                  vc = getVC(ta.getTrustedCert(), vcPos);
                  found = true;
                  break;
              }
          }
          if ( ! found )
            vc = getVC(chain[0], vcPos);
      }
      else
          vc = getVC(chain[1], vcPos);

      if ( vc != null)
        if ( ! vcUsed.add ( vc ) )  // vc already used
        {
          vcPos++;
          continue;
        }

      pkiva.log.LogManager.getLogger(this.getClass()).debug("checkValidity with vc:" + vc + ".Iteration:" + vcPos );
      if ( vcPos > 0 && vc == null )
        break; // no more vc's available

      try
      {
        result = checkValidity(chain,vc,policies, infoRequested, audit_id);
        lastError = null;
      }
      catch ( Throwable t )
      {
        pkiva.log.LogManager.getLogger(this.getClass()).warn("checkValidity with vc:" + vc + ".Error:" + t );
        lastError = t;
        result = null;
      }
      vcPos++;
//    } while (result == ValidationConstants.INTERNAL_SERVER_ERROR);
    } while ( lastError != null );

    if ( ( result == null ) && ( lastError != null ) )
    {
      throw new CertValidationException ( lastError.getMessage(), lastError );
    }

    return result;
  }
  }  
    
    /** Checks the validity of an incomplete certificate chain. The certificate chain
     * must be completed with out-of-band repository-based CA-certificates.
     * @param certificate Certificate to validate
     * @param policies Policies to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
//    protected short checkValidity(X509Certificate cert, Set policies) throws RemoteException{
//        try{
//            return checkValidity(getChain(cert),policies);
//        }
//        catch (CertPathBuilderException cpbe){
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("CertPathBuilder was unable to create a correct chain. Attempting to use 1-certificate chain.",cpbe);
//            return checkValidity(new X509Certificate[]{cert}, policies);//Maybe it is a first-level CA, will attempt to process it as an 1-element array
//        }
//        catch (GeneralSecurityException gse){
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking chain result: CERTCHAIN_NOT_FOUND due to exception ",gse);
//            return ValidationConstants.CERTCHAIN_NOT_FOUND;
//        }
//    }
    
    /** Checks the validity of a pkcs7
     * @param pkcs7 Byte serialization of pkcs7 to validate.
     * @param policies Policies to use.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     */
//    protected short checkValidity(byte[] pkcs7, Set policies) throws RemoteException{
//        try{
//            return checkValidity(getChain(pkcs7),policies);
//        }
//        catch(IOException ioe){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("Checking pkcs7 result: INTERNAL_SERVER_ERROR.",ioe);
//            return ValidationConstants.INTERNAL_SERVER_ERROR;
//        }
//    }
    
    /** This method validates the entire certificate chain with the given validation channel.
     * Expects forward order (end entity cert first), and no trust anchor passed (root
     * CA certificate). If there are TrustAnchors inside the array, they are eliminated.
     *
     * Uses the concrete SUNJCE implementation (CertPathValidator) for J2SE 1.4.2,
     * because it's more stable than BC one, and enforces validation of user-based
     * CertPathCheckers
     *
     * In the EJB is only implemented the basic validation, without CRL validation,
     * that is performed in the VCs (implemented with RAs).
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     * @param policies Set of policies that the certificate chain must support.
     * @param chain Certificate chain to validate
     * @param vc Validation channel to use.
     */
    protected CertValidationResponse checkValidity(X509Certificate[] chain, String vc, Set policies, boolean infoRequested, int audit_id) throws RemoteException
    {
      X509Certificate[] filtered;
      PKIXCertPathChecker chk = null;
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking chain validity using vc="+vc+" and policies="+policies);
      try
      {
        try {
            //An empty chain is not considered valid.
            if(chain.length==0)
                throw new CertPathValidatorException("Empty validation chain.");
            //If chain consists only in one trusted anchor, check if it is just valid.
            if(chain.length==1 && isInKnownTrustAnchors(chain[0])){
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Chain consists only on one TrustAnchor, and is known.");
                chain[0].checkValidity( TimeProvider.getCurrentTime().getTime() );
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking chain result: GOOD.");
//                return ValidationConstants.GOOD;
                CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.GOOD );
                //response.setValidationChannel ( CertValidationResponse.ONLY_TRUSTANCHOR );
                return response;
            }
            else{
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Excluding TrustAnchors from chain.");
                //Exclude Trust Anchors from given chain.
                filtered = CertUtils.excludeTrustAnchors(chain);
            }
            //Otherwise, we have to remove trust anchors from chain, ans check the whole chain.
            if(filtered.length==0)// If chain with Trust Anchors removed is empty, then assume it was INVALID
                throw new CertPathValidatorException("Validation chain contained only trust anchors.");

            List certchain = Arrays.asList(filtered);
            pkiva.log.LogManager.getLogger(this.getClass()).debug("certchain list has size:" + certchain.size());

            //Ensure providers are registered. Should be done somewhere else
            int iPKIVAJCEProvider = Security.addProvider(new PKIVAJCEProvider());
            int iBouncyCastleProvider = Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            pkiva.log.LogManager.getLogger(this.getClass()).debug("iPKIVAJCEProvider:" + iPKIVAJCEProvider);
            pkiva.log.LogManager.getLogger(this.getClass()).debug("iBouncyCastleProvider:" + iBouncyCastleProvider);
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("############### PROVIDERS");
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("this:" + this);
//
//            Provider[] provs = Security.getProviders();
//            if ( provs != null )
//            {
//              pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders length:" + provs.length);
//              for ( int i = 0; i < provs.length; i++ )
//                pkiva.log.LogManager.getLogger(this.getClass()).debug(i + " Provider:" + provs[i]);
//            }
//            else
//              pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders null");
//
//
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("removeProvider PKIVAJCEProvider ");
//            Security.removeProvider(PKIVAJCEProvider.PROVIDER_NAME);
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("addProvider new PKIVAJCEProvider() " + Security.addProvider(new PKIVAJCEProvider()));
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("addProvider bouncycastle " + Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()));
//
//            provs = Security.getProviders();
//            if ( provs != null )
//            {
//              pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders length:" + provs.length);
//              for ( int i = 0; i < provs.length; i++ )
//                pkiva.log.LogManager.getLogger(this.getClass()).debug(i + " Provider:" + provs[i]);
//            }
//            else
//              pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders null");
//
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("############### PROVIDERS");

            
            //Obtain the certStore
            CertStore store = CertStore.getInstance("ResourceAdapter",null,"PKIVA_JCE");
            //Get a CertPath implementation from SUN, and build the certpath
            CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath( certchain );
            //obtain the concrete SUN implementation that is reviewed and approved by us, and complies well with PKIX RFC3280
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Using CPV: " + cpv);
            
            //set parameters to make validator work
            PKIXParameters param = new PKIXParameters(CertStoreProvider.getTrustAnchors());
            
            param.setRevocationEnabled(false);//we don't use RFC3280 inlined CRL validation, instead we do it in the RAs
            //The checker to use, determined by the validation channel.
            chk = getChecker(filtered,vc);
            if(chk==null)
                throw new CertPathValidatorException("Cannot determine the kind of checker for validation channel "+vc);
            param.addCertPathChecker(chk);
            //the certstore to work with
            param.addCertStore(store);
            //we use BC, that includes mostly-used SHA1withRSA
            param.setSigProvider("BC");
            //put the date obtained throug the date provider.
            param.setDate(TimeProvider.getCurrentTime().getTime());
            
            // realize validation per se
            // will throw exception if wrong
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Using Certpath with "+cp.getCertificates().size()+" elements to validate.");
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Using Initial Policies: "+policies+" with ExplicitPolicyRequired=true");


            //Add acceptable policies.
            param.setInitialPolicies(policies);
            param.setExplicitPolicyRequired(false);
            
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, param);
            //pkiva.log.LogManager.getLogger(this.getClass()).debug("CPV: " + cpv);
            //pkiva.log.LogManager.getLogger(this.getClass()).debug("Result from CPV: " + result);
            //pkiva.log.LogManager.getLogger(this.getClass()).debug("Policy tree from CPV: " + result.getPolicyTree().getClass());

            //Checks expiration for trustAnchor used.
            result.getTrustAnchor().getTrustedCert().checkValidity( TimeProvider.getCurrentTime().getTime() );
            
            //if we get this point, by spec (see PKIXCertPathValidatorResult), the validation result is OK, so return GOOD state.
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking chain result: GOOD.");
//            return ValidationConstants.GOOD;
            CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.GOOD );
            response.setValidationChannel ( vc );
            response.setResult ( result );

            ValidationObject valInfo = null;
            if ( infoRequested )
            {
            	/*
              if ( result instanceof pkiva.providers.jce.certpath.PKIVAJCECertPathValidatorResult)
              {
                pkiva.providers.jce.certpath.PKIVAJCECertPathValidatorResult myResult = (pkiva.providers.jce.certpath.PKIVAJCECertPathValidatorResult) result;

                valInfo = myResult.getValInfo();
                response.setValidationInfo ( valInfo );

                pkiva.log.LogManager.getLogger(this.getClass()).debug("info object added to response");
              }
              */
            }

            auditResponse ( audit_id, response.getStateDescription(), vc, valInfo, result );
            return response;
             }
        //if we get a cert path validator exception, we have to analyze the cause to find the problem and give notice to the user
        catch(CertPathValidatorException cpve) {
          Throwable realCause = cpve.getCause();
          if ( realCause == null )
            realCause = cpve;
          
          pkiva.log.LogManager.getLogger(this.getClass()).debug("realCause:" + realCause.getClass().getName());
          if ( realCause instanceof CertStoreException)
          {
            Throwable newRealCause = ( (CertStoreException) realCause).getCause();
            if ( newRealCause != null )
              realCause = newRealCause;
            pkiva.log.LogManager.getLogger(this.getClass()).debug("new realCause:" + realCause.getClass().getName());
          }
          
          if ( realCause instanceof CertificateChainRevocationException)
          {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: REVOKED due to exception ",realCause);

              // diriarte: 20050324 -> anyadir suspended (hold) como salida
              short errorCode = CertValidationResponse.REVOKED;
              if ( ((CertificateChainRevocationException)realCause).getRevocationReason() == 6  )
                errorCode = CertValidationResponse.SUSPENDED;

            CertValidationResponse response = new CertValidationResponse ( errorCode );
            response.setValidationChannel ( vc );
            response.setErrorCause ( realCause );

            if ( infoRequested )
              response.setValidationInfo( ((CertificateChainRevocationException)realCause).getValidationObject());

            auditResponse ( audit_id, response.getStateDescription(), vc, ((CertificateChainRevocationException)realCause).getValidationObject(), null );

            return response;
          }
          else if ( realCause instanceof UnknownCertificateChainRevocationStatusException)
          {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: UNKNOWN due to exception ",realCause);
            CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.UNKNOWN );
            response.setValidationChannel ( vc );
            response.setErrorCause ( realCause );

            if ( infoRequested )
              response.setValidationInfo( ((UnknownCertificateChainRevocationStatusException)realCause).getValidationObject());

            auditResponse ( audit_id, response.getStateDescription(), vc, ((UnknownCertificateChainRevocationStatusException)realCause).getValidationObject(), null );

            return response;
          }
          else if ( realCause instanceof RevocationCheckingException) 
          {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Error checking chain",realCause);

            auditError ( audit_id, realCause );

            throw new CertValidationException ( realCause.getMessage(), realCause );
          }
          else if ( realCause instanceof CertPathValidatorException)
          {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: INVALID_CERTCHAIN due to exception ",realCause);
            CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.INVALID_CERTCHAIN );
            response.setErrorCause ( realCause );

            auditError ( audit_id, realCause );

            return response;
          }
          else if ( realCause instanceof CertificateExpiredException)
          {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: EXPIRED due to exception " + realCause.getMessage());
            CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.EXPIRED );
            response.setErrorCause ( realCause );

            auditResponse ( audit_id, response.getStateDescription(), vc, null, null );
//            auditError ( audit_id, realCause );

            return response;
          }
          else if ( realCause instanceof CertificateNotYetValidException)
          {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: NOT_YET_VALID due to exception " + realCause.getMessage());
            CertValidationResponse response = new CertValidationResponse ( CertValidationResponse.NOT_YET_VALID );
            response.setErrorCause ( realCause );

              auditResponse ( audit_id, response.getStateDescription(), vc, null, null );
//            auditError ( audit_id, realCause );

            return response;
          }
          else
          {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Unexpected error",realCause);

            auditError ( audit_id, realCause );

            throw new CertValidationException ( realCause.getMessage(), realCause );
          }
          
//        return ValidationConstants.INVALID_CERTCHAIN;
        }
        catch(java.security.cert.CertificateException ce) {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Checking chain result: INVALID_CERTCHAIN due to exception ",ce);
//            return ValidationConstants.INVALID_CERTCHAIN;
            CertValidationResponse response =  new CertValidationResponse ( CertValidationResponse.INVALID_CERTCHAIN );
            // ??? response.setValidationChannel ( CertValidationResponse. );
            response.setErrorCause ( ce );

            auditError ( audit_id, ce );

            return response;
        }
        //in other case, we assume that the exception is due to an internal error, and we must return a 500-style error
        catch(Throwable e) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Error checking chain" ,e);
//            return ValidationConstants.INTERNAL_SERVER_ERROR;

            auditError ( audit_id, e );

            throw new CertValidationException ( e.getMessage(), e );
        }
      } // end try auditing
      catch ( AuditingException e )
      {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Error checking chain" ,e);
            throw new CertValidationException ( e.getMessage(), e );
      }
      catch ( RemoteException e )
      {
        throw e;
      }
    }
    
    protected void auditError ( int audit_id, Throwable t ) throws AuditingException
    {
      CertValidation auditOper = new CertValidation ();
      auditOper.setError ( t );
      pkiva.log.AuditManager.getAuditer(this.getClass()).auditResponse ( auditOper, audit_id );
    }

    protected void auditResponse(int audit_id, String state, String vc, ValidationObject valInfo, PKIXCertPathValidatorResult result) throws AuditingException {
      try
      {
        CertValidation auditOper = new CertValidation ();
        auditOper.setState ( state );
        auditOper.setVCResponse ( vc );

        if (result != null)
        {
          auditOper.setTrustAnchor ( result.getTrustAnchor() );
          PolicyNode policies = result.getPolicyTree();
          if ( policies != null )
            auditOper.setPolicyTree ( policies.toString() );
        }

        if ( valInfo instanceof OCSPValidationInfo )
        {
          OCSPValidationInfo info = (OCSPValidationInfo) valInfo;
          auditOper.setRevocationObject ( info.getOCSPData() );
        }
        else if ( valInfo instanceof CRLValidationInfo )
        {
          CRLValidationInfo info = (CRLValidationInfo) valInfo;
          Collection crls = info.getCrls ();

          Iterator crlIterator = crls.iterator();
          if ( crlIterator.hasNext() )
          {
            X509CRL crl = (X509CRL) crlIterator.next();
            auditOper.setRevocationObject ( crl.getEncoded() );
          }
        }

        pkiva.log.AuditManager.getAuditer(this.getClass()).auditResponse ( auditOper, audit_id );
      }
      catch ( AuditingException t )
      {
        throw t;
      }
      catch ( Throwable t )
      {
        throw new AuditingException ( t.getMessage(), t );
      }
    }

    /** Checks the validity of an incomplete certificate chain. The certificate chain
     * must be completed with out-of-band repository-based CA-certificates.
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     * @param policies Set of policies that the certificate chain must support.
     * @param certificate Certificate to validate
     * @param vc Validation channel to use.
     */
//    protected short checkValidity(X509Certificate certificate, String vc, Set policies) {
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking certificate validity using vc="+vc);
//        try{
//            return checkValidity(getChain(certificate),vc,policies);
//        }
//        catch (CertPathBuilderException cpbe){
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("CertPathBuilder was unable to create a correct chain. Attempting to use 1-certificate chain.",cpbe);
//            return checkValidity(new X509Certificate[]{certificate}, vc, policies);//Maybe it is a first-level CA, will attempt to process it as an 1-element array
//        }
//        catch (GeneralSecurityException gse){
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking chain result: CERTCHAIN_NOT_FOUND due to exception ",gse);
//            return ValidationConstants.CERTCHAIN_NOT_FOUND;
//        }
//    }
    
    /**
     * Constructs a certificate chain starting in given certificate.
     * @param certificate The certificate to use as end point for the chain
     * @return The certificate chain built, whose first element is given certificate
     * @exception CertPathBuilderException if the chain to a TrustAnchor cannot be found
     * @exception GeneralSecurityException if any other security exception happens (in builder algorithm)
     */
    protected X509Certificate[] getChain(X509Certificate certificate) throws CertPathBuilderException,GeneralSecurityException{
        //If it is a trust anchor, we return the single chain that it represents.
        if ( CertUtils.isTrustAnchor(certificate) ){
            return new X509Certificate[]{certificate};
        }
        //Ensure providers are registered. Should be done somewhere else
        int iPKIVAJCEProvider = Security.addProvider(new PKIVAJCEProvider());
        int iBouncyCastleProvider = Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        pkiva.log.LogManager.getLogger(this.getClass()).debug("iPKIVAJCEProvider:" + iPKIVAJCEProvider);
        pkiva.log.LogManager.getLogger(this.getClass()).debug("iBouncyCastleProvider:" + iBouncyCastleProvider);
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("############### PROVIDERS");
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("this:" + this);
//
//        Provider[] provs = Security.getProviders();
//        if ( provs != null )
//        {
//          pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders length:" + provs.length);
//          for ( int i = 0; i < provs.length; i++ )
//            pkiva.log.LogManager.getLogger(this.getClass()).debug(i + " Provider:" + provs[i]);
//        }
//        else
//          pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders null");
//
//
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("removeProvider PKIVAJCEProvider ");
//        Security.removeProvider(PKIVAJCEProvider.PROVIDER_NAME);
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("addProvider new PKIVAJCEProvider() " + Security.addProvider(new PKIVAJCEProvider()));
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("addProvider bouncycastle " + Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()));
//
//        provs = Security.getProviders();
//        if ( provs != null )
//        {
//          pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders length:" + provs.length);
//          for ( int i = 0; i < provs.length; i++ )
//            pkiva.log.LogManager.getLogger(this.getClass()).debug(i + " Provider:" + provs[i]);
//        }
//        else
//          pkiva.log.LogManager.getLogger(this.getClass()).debug("getProviders null");
//
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("############### PROVIDERS");

        //CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","PKIVA_JCE");
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","BC");
        //Construct a selector that filters certificates whose subject is current one's issuer.
        X509CertSelector sel = new X509CertSelector();
        try{
            sel.setSubject(certificate.getIssuerX500Principal().getEncoded());
        }
        catch(IOException ioe){//Should never happen.
            pkiva.log.LogManager.getLogger(this.getClass()).warn("Exception creating selector in getChain(X509Certificate certificate):",ioe);
        }
        PKIXBuilderParameters params = new PKIXBuilderParameters(CertStoreProvider.getTrustAnchors(),sel);
        CertStore store = CertStore.getInstance("ResourceAdapter",null,"PKIVA_JCE");
        params.addCertStore(store);
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Building CertPathBuilderResult.");
        //Attempt to construct the certificate path
        CertPathBuilderResult cpbr = cpb.build(params);
        //Convert result to an array.
        X509Certificate[] chain = (X509Certificate[])cpbr.getCertPath().getCertificates().toArray(new X509Certificate[cpbr.getCertPath().getCertificates().size()]);
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Created certificate chain: "+certificateChainToString(chain));
        //Create an array with one element more and append the certificate being checked (at the beginning)
        X509Certificate[] chainComplete = new X509Certificate[1+chain.length];
        chainComplete[0] = certificate;
        System.arraycopy(chain, 0, chainComplete, 1, chain.length);
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Created full certificate chain: "+certificateChainToString(chainComplete));
        //The chain  is created.
        return chainComplete;
    }
    
    /**
     * Represents a X509Certificate[] as a String, for display purposes only.
     * @param chain Chain to represent.
     * @return a String representation of a X509Certificate chain.
     */
    private String certificateChainToString(X509Certificate[] chain){
        StringBuffer sb = new StringBuffer();
        sb.append("{ SN=");
        for(int i=0;i<chain.length;i++){
            if (i>0) sb.append(", SN=");
            sb.append(chain[i].getSerialNumber());
        }
        sb.append(" }");
        return sb.toString();
    }
    
    /** Checks the validity of a pkcs7
     * @return ValidationConstants.GOOD if chain is OK, ValidationConstants.INVALID_CHAIN
     * if it is not OK, or ValidationConstants.INVALID_CHAIN or
     * ValidationConstants.INTERNAL_SERVER_ERROR if an error occurs.
     * @param policies Set of policies that the certificate chain must support.
     * @param pkcs7 Byte serialization of pkcs7 to validate.
     * @param vc Validation channel to use.
     */
//    protected short checkValidity(byte[] pkcs7, String vc, Set policies){
//        try{
//            return checkValidity(getChain(pkcs7),vc,policies);
//        }
//        catch(IOException ioe){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("Checking pkcs7 result: INTERNAL_SERVER_ERROR.",ioe);
//            return ValidationConstants.INTERNAL_SERVER_ERROR;
//        }
//    }
    
    /** Nuevo metodo de validation
     *  Recibe un objeto CertValidationRequest, analiza la informacion contenida y llama al que toque
     */
    public CertValidationResponse checkValidity(CertValidationRequest request) throws RemoteException
    {
      try
      {
          X509Certificate[] chain = null;
          try {
              chain = getChain(request);
              if ( chain == null )
                throw new CertValidationException ( "Couldn't get Certificate Chain");
              if (chain.length==0)
                throw new CertPathValidatorException("Empty validation chain.");
          } catch (NoSuchAlgorithmException e) {
              pkiva.log.LogManager.getLogger(this.getClass()).error("Error building chain:", e);
              throw e;
          } catch (Exception e) {
              pkiva.log.LogManager.getLogger(this.getClass()).error("Error building chain:", e);
              CertValidationResponse response = new CertValidationResponse(CertValidationResponse.INVALID_CERTCHAIN);
              response.setErrorCause(e);
              return response;
          }

        Set policies = (Set) request.getParameter ( CertValidationRequest.POLICIES );
        if ( policies == null )
          policies = Collections.EMPTY_SET;

        boolean infoRequested = false;
        Boolean infoRequestedBool = (Boolean) request.getParameter ( CertValidationRequest.REQUEST_INFO );
        if ( infoRequestedBool != null )
          infoRequested = infoRequestedBool.booleanValue();
        pkiva.log.LogManager.getLogger(this.getClass()).debug("InfoRequested:" + infoRequested);

        String vc = (String) request.getParameter ( CertValidationRequest.VALIDATION_CHANNEL );

        // Changes auditing Aug-04
        int audit_id = auditRequest( chain[0], policies, vc );

        CertValidationResponse response;
        if ( vc == null )
        {
          response = checkValidity ( chain, policies, infoRequested, audit_id );
        }
        else
        {
          response = checkValidity ( chain, vc, policies, infoRequested, audit_id );
        }

        response.setChain(chain);
        response.setPolicies(policies);
        return response;
      }
      catch ( CertValidationException cpe )
      {
        throw cpe;
      }
      catch ( Throwable t )
      {
        throw new CertValidationException ( t.getMessage(), t );
      }
    }
    
    protected int auditRequest ( X509Certificate cert, Set policies, String vc ) throws AuditingException
    {
      CertValidation auditOper = new CertValidation ();
      auditOper.setCert ( cert );
      if ( ( policies != null ) && ( ! policies.isEmpty() ) )
        auditOper.setPolicies ( policies.toString() );
      if ( vc != null )
        auditOper.setVCRequest ( vc );

      return pkiva.log.AuditManager.getAuditer(this.getClass()).auditIncomplete ( auditOper );
    }
    
    protected X509Certificate[] getChain(CertValidationRequest request) 
      throws IllegalArgumentException, IOException, CertPathBuilderException, GeneralSecurityException
    {
      if ( request == null )
        throw new IllegalArgumentException ( "NULL Certificate Validation Request" );
      
      if ( request.getChain() != null )
        return request.getChain();
      
      if ( request.getCert() != null )
        return getChain ( request.getCert() );
      
      if ( request.getPkcs7() != null )
        return getChain ( request.getPkcs7() );
      
      throw new IllegalArgumentException ( "Certificate Validation Request with no certificate" );
    }
    
    /**
     * Reads the certificate chain inside a pkcs#7.
     *
     */
    protected X509Certificate[] getChain(byte[] pkcs7) throws IOException{
        ByteArrayInputStream bais = new ByteArrayInputStream(pkcs7);
        ASN1InputStream asn1is = new ASN1InputStream(bais);
        DERSequence obj = (DERSequence)asn1is.readObject();
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Read object from pkcs7");
        Enumeration objects = obj.getObjects();
        // Look for an object tagged 0. This object contains the certificate sequence.
        DERSequence sequence = null;
        while(objects.hasMoreElements()){
            DERObject derObj = (DERObject)objects.nextElement();
            if(derObj instanceof DERTaggedObject){
                DERTaggedObject objTagged = (DERTaggedObject)derObj;
                if(objTagged.getTagNo() == 0){
                    sequence = (DERSequence)objTagged.getObject();
                    break;
                }
            }
        }
        if(sequence==null){//No certificates found inside the pkcs7
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Checking pkcs7 result: No certificates found.");
            return new X509Certificate[0];
        }
        //Construct a SignedData object based on sequence elements.
        SignedData data = SignedData.getInstance(sequence);
        asn1is.close();
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Processing certificates in object read from pkcs7");
        Vector v = new Vector();
        for(Enumeration e = data.getCertificates().getObjects();e.hasMoreElements();v.add(e.nextElement()));
        X509Certificate[] certs = new X509Certificate[v.size()];
        
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Converting vector to array...");
        //Conversion requires extracting a X509Certificate from the DERsequence.
        for(int i=0;i<v.size();i++){
            DERSequence seq = (DERSequence)v.elementAt(i);
            try{//Another possibility (slower) is to use the pkiva.parsing.Certificate getX509Certificate() method
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ASN1OutputStream aos = new ASN1OutputStream(bos);
                aos.writeObject(seq);
                aos.flush();
                ByteArrayInputStream bis = new ByteArrayInputStream( bos.toByteArray() );
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                certs[i] = (X509Certificate)cf.generateCertificate(bis);
                bis.close();
                aos.close();
            }
            catch(Exception e){
                pkiva.log.LogManager.getLogger(this.getClass()).error("Obtaining X509Certificate from pkcs7",e);
            }
        }
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Read "+certs.length+" certificates from pkcs7.");
        //All the certificates are read.
        //Note that we assume that they are in forward order. Otherwise, the order would have to be reversed.
        return certs;
    }
    
    /** Returns the CertPathChecker associated to given validation channel for given certificate chain.
     * @param vc The validation channel to use
     * @param filtered The X509Certificate chain, where trustAnchors have already been removed.
     * @return A PKIXCertPathChecker to use with given chain and Validation Channel.
     */
    protected PKIXCertPathChecker getChecker(X509Certificate[] filtered, String vc){
        pkiva.log.LogManager.getLogger(this.getClass()).debug("getChecker() for vc="+vc);
        if(PKIXDistributionPoint.PKIXCRLDP.equals(vc)){
            try{
                //Create a CRLCertPathChecker and return it.
                PublicKey pk = getTrustPublicKey(CertStoreProvider.getTrustAnchors(),filtered[filtered.length-1]);
                CertStore store = CertStore.getInstance("ResourceAdapter",null,"PKIVA_JCE");
                Vector certStores = new Vector(1);
                certStores.add(store);
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Returning a CRLCertPathChecker for vc="+vc);
                return new CRLCertPathChecker( pk ,certStores, "BC", TimeProvider.getCurrentTime().getTime());
            }
            catch(Exception e){
                pkiva.log.LogManager.getLogger(this.getClass()).error("Cannot determine PKIXCertPathChecker to use with channel "+vc);
                return null;
            }
        }
        else if(PKIXDistributionPoint.PKIXOCSPDP.equals(vc)){
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Returning a OCSPCertPathChecker for vc="+vc);
            return new OCSPCertPathChecker();
        }
        else
            return null;
    }
    
    /**
     * @return The highest priority Validation Channel for a given CA.
     *
     *
     */
    protected String getVC(X509Certificate cert){
        return getVC ( cert, 0 );
    }
    
    /**
     * @return The Validation Channel with given position (ordered by priority) for a given CA. null if no such element in list
     *
     *
     */
    protected String getVC(X509Certificate cert, int pos){
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Determining VC for certificate SBJ="+cert.getSubjectDN());
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Determining VC for certificate SN="+cert.getSerialNumber());
      for(Iterator it = CertStoreProvider.getCAEstructuralElements().iterator();it.hasNext();){
          EstructuralElement el = (EstructuralElement)it.next();
          if(
          cert.getIssuerDN().equals(el.getCACertificate().getIssuerDN())
          &&
          cert.getSerialNumber().equals(el.getCACertificate().getSerialNumber())
          ){
              List dps = el.getDistributionPoints();
              if ( dps != null && dps.size() > pos )
              {
                PKIXDistributionPoint dp = (PKIXDistributionPoint) dps.get( pos );

                pkiva.log.LogManager.getLogger(this.getClass()).debug("Returning VC for certificate SBJ="+cert.getSubjectDN()+" is vc="+dp.getType ());
                //pkiva.log.LogManager.getLogger(this.getClass()).debug("Returning VC for certificate SN="+cert.getSerialNumber()+" is vc="+dp.getType ());
                return dp.getType ();
              }
              else
                return null;
          }
      }
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Returning VC for certificate SBJ="+cert.getSubjectDN()+" is null");
      //pkiva.log.LogManager.getLogger(this.getClass()).warn("Returning VC for certificate SN="+cert.getSerialNumber()+" is null");
      return null;
    }
    
    
    /**
     * Checks if given certificate belongs to known TrustAnchors
     * @param cert The certificate to check
     * @return true if it is a known TurstAnchor, false otherwise
     */
    protected boolean isInKnownTrustAnchors(X509Certificate cert){
        Set s = CertStoreProvider.getTrustAnchors();
        for(Iterator it = s.iterator();it.hasNext();){
            TrustAnchor ta = (TrustAnchor)it.next();
            if(ta.getTrustedCert().equals(cert))
                return true;
        }
        if(CertUtils.isTrustAnchor(cert))
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Certificate IS TrustAnchor, but we don't trust it.");
        return false;
    }
    
    /**
     * Determine which (if any) trust anchor refers given certificate, and returns its public key.
     *
     * @param trustAnchors All available trusted anchors
     * @param cert certificate to determine which trusted anchor signs it.
     * @return returns the trust anchor public key or null if nothing matches
     */
    protected PublicKey getTrustPublicKey(Collection trustAnchors, X509Certificate cert )
    {
      X509Certificate trust = CertUtils.getTrustAnchor(trustAnchors, cert );
      if ( trust != null)
        return trust.getPublicKey();
      else
        return null;
    }
    
    /**
     * Default true.
     */
    protected boolean isStrictPolicyRequired(){
        try{
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            String s = svcLoc.getProperty("pkiva.validation.PolicyRequiredInAllCertificates");
            if(s!=null){
                return new Boolean(s).booleanValue();
            }
        }
        catch( pkiva.exceptions.ServiceLocatorException sle){
            pkiva.log.LogManager.getLogger(this.getClass()).error("Service locator unreachable: ",sle);
        }
        return true;
    }

//    protected static short translateVC( String vc )
//    {
//      short out = CertValidationResponse.UNKNOWN;
//      
//      if ( vc != null )
//        if ( PKIXDistributionPoint.PKIXCRLDP.equalsIgnoreCase( vc ) )
//          out = CertValidationResponse.CRL;
//        else if ( PKIXDistributionPoint.PKIXOCSPDP.equalsIgnoreCase( vc ) )
//          out = CertValidationResponse.OCSP;
//      return out;
//    }
    
    /**
     * @throws CreateException
     */
    public void ejbCreate() throws CreateException { }
    /**
     * @param theContext
     */
    public void setSessionContext(SessionContext theContext) {this.context = theContext;}
    public void ejbActivate()  { }
    public void ejbPassivate()  { }
    public void ejbRemove()   { }
}
