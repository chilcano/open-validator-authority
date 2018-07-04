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
package pkiva.validation;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Iterator;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Extension;
import java.security.interfaces.DSAPublicKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.x509.CRLReason;

import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.KeyFactory;

import pkiva.services.*;
import pkiva.exceptions.*;
import pkiva.validation.crl.*;


public class CRLCertPathChecker extends GenericPKIXCertPathChecker {
    private final PublicKey mInitPubKey;
    private final List mStores;
    private final String mSigProvider;
    private final Date mCurrentTime;
    private PublicKey mPrevPubKey;
    private boolean mCRLSignFlag;
    private HashSet mPossibleCRLs;
    private HashSet mApprovedCRLs;
//    private boolean certRevoked = false;
    
    /**
     * Default Constructor.
     *
     * @param initPubKey initial PublicKey in the path
     * @param stores a List of CertStores for retreiving CRLs
     * @param sigProvider a String used to validate CRLs
     * @param testDate a Date representing the time against which to test, or
     * null which uses the current time
     */
    public CRLCertPathChecker(PublicKey initPubKey, List stores,
    String sigProvider, Date testDate)  {
    	
        mInitPubKey = initPubKey;
        mStores = stores;
        mSigProvider = sigProvider;
        
        if (testDate != null)
            mCurrentTime = testDate;
        else
            mCurrentTime = new Date();
    }
    
    /**
     * Initializes the internal state of the checker from parameters
     * specified in the constructor
     */
    public void init(boolean forward) throws CertPathValidatorException {
        if (forward)  {
            throw new CertPathValidatorException("forward checking "
            + "not supported");
        }
    }
    
    public Object clone(){
    	/*CRLCertPathChecker other = 
    		new CRLCertPathChecker(mInitPubKey, mStores, mSigProvider, mCurrentTime);    	

    	other.mPrevPubKey = this.mPrevPubKey;
    	other.mCRLSignFlag = this.mCRLSignFlag;
    	other.mPossibleCRLs = this.mPossibleCRLs;
    	other.mApprovedCRLs = this.mApprovedCRLs;
    	
    	return other;*/
    	
    	return this;
    	
    }
    
    public boolean isForwardCheckingSupported() {
        return false;
    }
    
    public Set getSupportedExtensions() {
        return null;
    }
    
    public ValidationObject checkWithResponse(Certificate cert, Collection unresolvedCritExts) throws CertPathValidatorException 
    {
// diriarte: check !!
//Checking chain result: INVALID_CERTCHAIN due to exception: java.security.cert.CertPathValidatorException: unrecognized critical extension(s)
        unresolvedCritExts.clear();

        X509Certificate currCert = (X509Certificate) cert;
        
        //Si es la raíz, mPrevPubKey = su key;
        if (((X509Certificate)cert).getBasicConstraints()>-1) {
            //this certificate is a CA, check whether it's a trust anchor (self-signed root) or it's an intermediate CA
            if ( ((X509Certificate)cert).getIssuerDN().equals( ((X509Certificate)cert).getSubjectDN() ) )
                mPrevPubKey=cert.getPublicKey();
        }
        
        if(mPrevPubKey==null){
        	mPrevPubKey = mInitPubKey;
            mCRLSignFlag = true;            
        }
        
        verifyRevocationStatus(currCert, mPrevPubKey, mCRLSignFlag);
        
        // Make new public key if parameters are missing
        PublicKey cKey = currCert.getPublicKey();
        if (cKey instanceof DSAPublicKey &&
        ((DSAPublicKey)cKey).getParams() == null) {
            // cKey needs to inherit DSA parameters from prev key
            cKey = makeInheritedParamsKey(cKey, mPrevPubKey);
        }
        
        mPrevPubKey = cKey;
        mCRLSignFlag = CertUtils.certCanSignCrl(currCert);

        return new CRLValidationInfo ( false, mApprovedCRLs );
    }
    
    static PublicKey makeInheritedParamsKey(PublicKey keyValueKey,
    PublicKey keyParamsKey) throws CertPathValidatorException {
        PublicKey usableKey;
        if (!(keyValueKey instanceof DSAPublicKey) ||
        !(keyParamsKey instanceof DSAPublicKey))
            throw new CertPathValidatorException("Input key is not " +
            "appropriate type for " +
            "inheriting parameters");
        DSAParams params = ((DSAPublicKey)keyParamsKey).getParams();
        if (params == null)
            throw new CertPathValidatorException("Key parameters missing");
        try {
            BigInteger y = ((DSAPublicKey)keyValueKey).getY();
            KeyFactory kf = KeyFactory.getInstance("DSA");
            DSAPublicKeySpec ks = new DSAPublicKeySpec(y,
            params.getP(),
            params.getQ(),
            params.getG());
            usableKey = kf.generatePublic(ks);
        } catch (Exception e) {
            throw new CertPathValidatorException("Unable to generate key with" +
            " inherited parameters: " +
            e.getMessage(), e);
        }
        return usableKey;
    }
    
    public boolean check(X509Certificate currCert, PublicKey prevKey,
    boolean signFlag) throws CertPathValidatorException {
        verifyRevocationStatus(currCert, prevKey, signFlag);
        return CertUtils.certCanSignCrl(currCert);
    }
    
    private void verifyRevocationStatus(X509Certificate currCert,
    PublicKey prevKey, boolean signFlag) throws CertPathValidatorException {
        String msg = "revocation status";
        pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus() ---checking " + msg + "...");
        if (!signFlag)
            throw new CertPathValidatorException("cert can't vouch for CRL");
        
        // to start, get the entire list of possible CRLs
        X500Principal certIssuer = currCert.getIssuerX500Principal();
        
        // init the state for this run
        mPossibleCRLs = new HashSet();
        mApprovedCRLs = new HashSet();
        
        try {
            X509CRLSelector sel = new X509CRLSelector();
            sel.setCertificateChecking(currCert);
            //sel.setDateAndTime(mCurrentTime);
            
            // add the default issuer string
            sel.addIssuerName(certIssuer.getName("RFC2253"));
            //CertPathHelper.addIssuer(sel, certIssuer);
            
            Iterator i = mStores.iterator();
            while (i.hasNext()) {
                mPossibleCRLs.addAll(((CertStore) i.next()).getCRLs(sel));
            }
            /*DistributionPointFetcher store =
                DistributionPointFetcher.getInstance();
            mPossibleCRLs.addAll(store.getCRLs(sel));*/
        } catch (CertStoreException e) {
            throw new CertPathValidatorException ( e.getMessage(), e );
        } catch (Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus() unexpected exception: " , e);
            throw new CertPathValidatorException(e.getMessage(), e);
        }
        
        if (mPossibleCRLs.isEmpty()) {
            // we are assuming the directory is not secure,
            // so someone may have removed all the CRLs.
            throw new CertPathValidatorException(msg +" check failed: no CRL found");
        }
        pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus() mPossibleCRLs.size() = " + mPossibleCRLs.size());
        // Now that we have a list of possible CRLs, see which ones can
        // be approved                                       CNP2_demo.pfx
        Iterator iter = mPossibleCRLs.iterator();
        while (iter.hasNext()) {
            X509CRL crl = (X509CRL) iter.next();
            if (verifyPossibleCRL(crl, certIssuer, prevKey)) {
                mApprovedCRLs.add(crl);
            }
        }
        pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus() after verifying mApprovedCRLs.size() = " + mApprovedCRLs.size());

        // make sure that we have at least one CRL that _could_ cover
        // the certificate in question
        if (mApprovedCRLs.isEmpty()) {
            //return;//For debug purposes, we ignore CRL's if no suitable CRL is found CALLER
            throw new CertPathValidatorException( "no possible CRLs", new UnknownCertificateChainRevocationStatusException("no possible CRLs") );
        }
        
        pkiva.log.LogManager.getLogger(this.getClass()).debug("starting the final sweep...");
        iter = mApprovedCRLs.iterator();
        BigInteger sn = currCert.getSerialNumber();
        pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus cert SN: " + pkiva.parsing.wrappers.DERObjectWrapper.toHexaString(sn));
        
        boolean hold = false;
        while (iter.hasNext()) {
            X509CRL crl = (X509CRL) iter.next();
            
            pkiva.log.LogManager.getLogger(this.getClass()).debug("verifyRevocationStatus looking inside CRL: {" );
            if(crl.getRevokedCertificates()!=null)
                for(Iterator it = crl.getRevokedCertificates().iterator();it.hasNext();){
                    X509CRLEntry entry = (X509CRLEntry) it.next();
                    pkiva.log.LogManager.getLogger(this.getClass()).debug("  "+pkiva.parsing.wrappers.DERObjectWrapper.toHexaString(entry.getSerialNumber()) );
                }
            pkiva.log.LogManager.getLogger(this.getClass()).debug("}" );
            
            
            X509CRLEntry entry = (X509CRLEntry) crl.getRevokedCertificate(sn);
            if (entry != null) {
                pkiva.log.LogManager.getLogger(this.getClass()).debug("VerifyRevocationStatus CRL entry: " + entry.toString());
                
                int reasonCode = 0;
                
                try {
                	BigInteger reason = null;
                	byte[] extensionValue = entry.getExtensionValue("2.5.29.21");
                	
                	if ( extensionValue != null ) {
                        ASN1InputStream asn1is = new ASN1InputStream(extensionValue);

                        CRLReason crlReasonExtension = new CRLReason( DEREnumerated.getInstance(asn1is.readObject()) );
                        reason = crlReasonExtension.getValue();
                	}
                	
                    // if reasonCode extension is absent, this is equivalent
                    // to a reasonCode value of unspecified (0)
                    pkiva.log.LogManager.getLogger(this.getClass()).debug("Reason code for revocation: " + reason +"("+reasonToString(reasonCode)+")");
                    if (reason == null) {
                        reasonCode = 0;
                    } else {
                        reasonCode = reason.intValue();
                    }
                } catch (Exception e) {
                    throw new CertPathValidatorException(e);
                }
                
                /*
                 * If reason code is CERTIFICATE_HOLD, continue to look
                 * for other revoked entries with different reasons before
                 * exiting loop.
                 */
                hold = (reasonCode == 6);
                
                /*
                 * The certificate fails the revocation check if it is not
                 * on hold and the reason code is not REMOVE_FROM_CRL, which
                 * indicates a certificate that used to be but is no longer on
                 * hold status. It should not be considered fatal.
                 */
                if (!hold
                && reasonCode != 8) {
//                  certRevoked = true;
                    CertificateChainRevocationException ccre = new CertificateChainRevocationException ("Certificate has been revoked via CRL, reason: " + reasonToString(reasonCode) );
                    ccre.setValidationObject ( new CRLValidationInfo ( true, mApprovedCRLs ) );
                    ccre.setRevocationReason(reasonCode);
                    throw new CertPathValidatorException( ccre );
                }
                
                /*
                 * Throw an exception if any unresolved critical extensions
                 * remain in the CRL entry
                 */
                Set unresCritExts = entry.getCriticalExtensionOIDs();
                if ((unresCritExts != null) && !unresCritExts.isEmpty()) {
                    /* remove any that we have processed */
                    unresCritExts.remove("2.5.29.21");
                    if (!unresCritExts.isEmpty())
                        throw new CertPathValidatorException("Unrecognized "
                        + "critical extension(s) in revoked CRL entry: " + unresCritExts);
                }
            }
        }
        
        if (hold) {
//            throw new CertPathValidatorException("Certificate is on hold");
            CertificateChainRevocationException ccre = new CertificateChainRevocationException ("Certificate is on hold" );
            ccre.setValidationObject ( new CRLValidationInfo ( true, mApprovedCRLs ) );
            ccre.setRevocationReason(6);
            throw new CertPathValidatorException( ccre );
        }
    }
    
    /**
     * Return a String describing the reasonCode value
     */
    private static String reasonToString(int reasonCode) {
        switch (reasonCode) {
            case 0:
                return "unspecified";
            case 1:
                return "key compromise";
            case 2:
                return "CA compromise";
            case 3:
                return "affiliation changed";
            case 4:
                return "superseded";
            case 5:
                return "cessation of operation";
            case 6:
                return "certificate hold";
            case 8:
                return "remove from CRL";
            default:
                return "unrecognized reason code";
        }
    }
    
    private boolean verifyPossibleCRL(X509CRL crl, X500Principal certIssuer,
    PublicKey prevKey) throws CertPathValidatorException {
        if (!crl.getIssuerX500Principal().equals(certIssuer)) {
            pkiva.log.LogManager.getLogger(this.getClass()).info("verifyPossibleCRL::CRL issuer does not match cert issuer");
            pkiva.log.LogManager.getLogger(this.getClass()).info("verifyPossibleCRL::certIssuer::" + certIssuer);
            pkiva.log.LogManager.getLogger(this.getClass()).info("verifyPossibleCRL::crl.getIssuerX500Principal()::" + crl.getIssuerX500Principal());

            return false;
        }
        
        try {
            pkiva.log.LogManager.getLogger(this.getClass()).debug("Verifying crl with public key.");
            crl.verify(prevKey, mSigProvider);
        } catch (Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("CRL signature failed to verify",e);
            return false;
        }
        
        Date nextUpdate = crl.getNextUpdate();
        if (nextUpdate != null && nextUpdate.before(mCurrentTime)) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("discarding stale CRL (nextUpdate is before required validation time)");
            return false;
        }
        
        Set unresCritExts = crl.getCriticalExtensionOIDs();
        if (unresCritExts != null && !unresCritExts.isEmpty()) {
            Iterator i = unresCritExts.iterator();
            while (i.hasNext())
                pkiva.log.LogManager.getLogger(this.getClass()).debug((String)i.next());
            throw new CertPathValidatorException("Unrecognized "
            + "critical extension(s) in CRL: " + unresCritExts);
        }
        
        return true;
    }
    
    /** Getter for property mApprovedCRLs.
     * @return Value of property mApprovedCRLs.
     *
     */
    /*public CRLValidationInfo getCRLValidationInfo( )
    {
      return new CRLValidationInfo ( certRevoked, mApprovedCRLs );
    }*/
    
}
