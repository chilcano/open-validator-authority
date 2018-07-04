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

import java.rmi.*;
import javax.ejb.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import pkiva.exceptions.*;
import pkiva.validation.*;
import pkiva.services.*;
import pkiva.log.*;
import pkiva.log.operations.*;
import java.security.*;
import java.util.*;
import java.io.*;

import org.bouncycastle.cms.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.*;


//import pkiva.ValidationConstants;
//import org.bouncycastle.jce.PKCS7SignedData;

/** This bean allows verification and creation of signatures. */
public class SignatureBean   implements SessionBean {
    private SessionContext context;
    
    /** Gets the signature for a clear text using a pkcs12
     * @param pkcs12 PKCS12 where to obtain the certificates to sign.
     * @param certAlias Alias inside PKCS12 of the Certificate to use in signature.
     * @param storePwd Password for the pkcs12
     * @param clearText Text to sign.
     * @throws SignerException If signature fails for any reason.
     * @return The signature for given clear text.
     */
    /*public byte[] getSignature(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText) throws  RemoteException, SignerException{
        try{
            pkiva.log.LogManager.getLogger(this.getClass()).info("SignatureBean.getSignature(). Parameters: pkcs12=" + pkcs12 + ", certAlias=" + certAlias +  ", storePwd=" + storePwd + ", clearText=" + clearText );
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.SignerHome home = (pkiva.logic.SignerHome)svcLoc.getHome("Signer",pkiva.logic.SignerHome.class);
            pkiva.logic.Signer s = home.create();
            return s.sign(pkcs12,certAlias,storePwd,clearText);
        }
        catch(SignerException hex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().SignerException " , hex );
            throw hex;
        }
        catch(RemoteException rex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().RemoteException " , rex );
            throw rex;
        }
        catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().Exception " , e );
            throw new SignerException("Could sign text due to internal error: "+e.getMessage());
        }
    }*/
    
    /** Gets the signature for a clear text using a pkcs12
     * @param pkcs12 PKCS12 where to obtain the certificates to sign.
     * @param certAlias Alias inside PKCS12 of the Certificate to use in signature.
     * @param storePwd Password for the pkcs12
     * @param clearText Text to sign.
     * @param algorithm algorithm to use
     * @throws RemoteException ejb
     * @throws SignerException If signature fails for any reason.
     * @return The signature for given clear text.
     */
    /*public byte[] getSignature(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText, String algorithm) throws  RemoteException, SignerException{
        try{
            pkiva.log.LogManager.getLogger(this.getClass()).info("SignatureBean.getSignature(). Parameters: pkcs12=" + pkcs12 + ", certAlias=" + certAlias +  ", storePwd=" + storePwd + ", clearText=" + clearText + ",algorithm=" + algorithm );
            ServiceLocator svcLoc=ServiceLocator.getInstance();
            pkiva.logic.SignerHome home = (pkiva.logic.SignerHome)svcLoc.getHome("Signer",pkiva.logic.SignerHome.class);
            pkiva.logic.Signer s = home.create();
            return s.sign(pkcs12,certAlias,storePwd,clearText,algorithm);
        }
        catch(SignerException hex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().SignerException " , hex );
            throw hex;
        }
        catch(RemoteException rex){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().RemoteException " , rex );
            throw rex;
        }
        catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.getSignature().Exception " , e );
            throw new SignerException("Could sign text due to internal error: "+e.getMessage());
        }
    }*/
    
    /** Verifies signature of a given text with a pkcs7
     * @param pkcs7 pkcs containing certificates and signature
     * @param texto Clear text to verify.
     * @throws DigitalSignatureValidationErrorException In case of error.
     * @return true if signature validation succeedes, false otherwise.
     */
    public boolean verifySignature(byte[] cms, byte[] dtbs) throws   DigitalSignatureValidationErrorException
		{
		SignatureValidation auditOper = new SignatureValidation ();

		try
			{
			ServiceLocator svcLoc=ServiceLocator.getInstance();

			pkiva.logic.CertificateValidatorHome cHome = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
			pkiva.logic.CertificateValidator cv = cHome.create();

			auditOper.setPKCS7 ( cms );
			if ( dtbs != null)	auditOper.setContent ( dtbs );

			//System.out.println("SignatureVerifierBean.verify(). Parameters: cms=" + cms + ", dtbs=" + dtbs);
            pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verifySignature(). Parameters: cms=" + cms + ", dtbs=" + dtbs );

            CMSSignedData s = null;

            if (dtbs != null && dtbs.length > 0)
                pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verifySignature().dtbs as string =" +  new String(dtbs));

            if (dtbs!=null) s = new CMSSignedData(new CMSProcessableByteArray(dtbs), cms); //detached case
            else s = new CMSSignedData(cms);

//			CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(new ASN1InputStream(new ByteArrayInputStream(cms)).readObject()));

			CertStore               certs = s.getCertificatesAndCRLs("Collection", "BC");
			SignerInformationStore  signers = s.getSignerInfos();
			Collection              c = signers.getSigners();
			Iterator                it = c.iterator();

			//System.out.println("Cryptographic Message contains "+signers.size()+" signatures");
			pkiva.log.LogManager.getLogger(this.getClass()).info("Cryptographic Message contains "+signers.size()+" signatures");

			while (it.hasNext())
				{
				SignerInformation   signer = (SignerInformation)it.next();

				//when dtbs!=null if first of all check the hash inside the CMS matches with that passed as a parameter.
//				if (dtbs != null && dtbs.length > 0)
//					{
//                    pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verifySignature().dtbs as string =" + dtbs == null ? "[null]" : new String(dtbs));
//					obtain the MD signed attribute
//					Attribute mdattr = signer.getSignedAttributes().get(new DERObjectIdentifier("1.2.840.113549.1.9.4"));
//					byte[] md = ((DEROctetString)mdattr.getAttrValues().getObjectAt(0)).getOctets();
//
//					System.out.println("Creating digest for the DTBS using algorithm "+signer.getDigestAlgOID());
//					//pkiva.log.LogManager.getLogger(this.getClass()).info("Creating digest for the DTBS using algorithm "+signer.getDigestAlgOID());
//
//					byte[] md2 = MessageDigest.getInstance(signer.getDigestAlgOID(),"BC").digest(dtbs);
//
//					if (!MessageDigest.isEqual(md, md2)) throw new Exception("Hash from the DTBS(length "+md2.length+") mismatch with that contained in the CMS(length "+md.length+").");
//
//					//System.out.println("Cryptographic digest for signer "+signers.size()+" correspond with the one from the dtbs.");
//					pkiva.log.LogManager.getLogger(this.getClass()).info("Cryptographic digest for signer "+signers.size()+" correspond with the one from the dtbs.");
//					}


				//System.out.println("Verifying signature for signer "+signer.getSID());
				pkiva.log.LogManager.getLogger(this.getClass()).info("Verifying signature for signer "+signer.getSID());

				Collection          certCollection = certs.getCertificates(signer.getSID());

				Iterator        certIt = certCollection.iterator();
				X509Certificate cert = (X509Certificate)certIt.next();

                pkiva.log.LogManager.getLogger(this.getClass()).info("cert class b4"+cert);
                // convert to Sun cert
                byte[] certCms = cert.getEncoded();
                CertificateFactory cfBC = CertificateFactory.getInstance("X.509", "BC");
                InputStream is = new ByteArrayInputStream(certCms);
                X509Certificate certBC = (X509Certificate) cfBC.generateCertificate(is);
                pkiva.log.LogManager.getLogger(this.getClass()).info("cert class after"+certBC);

				boolean verify = false;
				try
				{
					verify = signer.verify(cert.getPublicKey(), "BC");
				} 
				catch(org.bouncycastle.cms.CMSException e)
				{
					pkiva.log.LogManager.getLogger(this.getClass()).info("Couldn't validate signature due to content mismatch." , e );
					Exception underlying = e.getUnderlyingException();
					if ( underlying !=  null)
					{
						pkiva.log.LogManager.getLogger(this.getClass()).info("Underlying exception from BC CMSException is:" , underlying );
					}
					audit ( auditOper, false );

					return false;
				}

				if (verify)
					{
					//System.out.println("Signature statically verified for signer "+signer.getSID());
					pkiva.log.LogManager.getLogger(this.getClass()).info("Signature statically verified for signer "+signer.getSID());
                    pkiva.log.LogManager.getLogger(this.getClass()).info("verifying cert "+certBC);

					CertValidationResponse certificateValidation = cv.checkValidity( new CertValidationRequest ( certBC ) );

					if (! certificateValidation.isValid())
						{
						pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is incorrect, certificate chain used to sign is not trusted.");
						audit ( auditOper, false );
						return false;
						}
					}
				else return false;
				}

			pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is correct.");
			audit ( auditOper, true );

			return true;
			}
		catch(Exception e)
			{
            pkiva.log.LogManager.getLogger(this.getClass()).error("Couldn't validate signature due to an internal error." , e );
            audit ( auditOper, e );

            throw new DigitalSignatureValidationErrorException("Couldn't validate signature due to an internal error.", e );
			}
		}
    
    /** Verifies signature of a given text with a pkcs7
     * @param pkcs7 pkcs containing certificates and signature
     * @throws DigitalSignatureValidationErrorException In case of error.
     * @return true if signature validation succeedes, false otherwise.
     */
    public boolean verifySignature(byte[] pkcs7) throws  DigitalSignatureValidationErrorException{
        return verifySignature(pkcs7,null);
    }
    
    /** Verifies signature of a given text with a pkcs7
     * @param pkcs7 pkcs containing certificates and signature
     * @param digest Text digest to verify.
     * @throws DigitalSignatureValidationErrorException In case of error.
     * @return true if signature validation succeedes, false otherwise.
     */
    public boolean verifyDigest(byte[] cms, byte[] digest) throws   DigitalSignatureValidationErrorException
		{
        SignatureValidation auditOper = new SignatureValidation ();

		try
			{
			ServiceLocator svcLoc=ServiceLocator.getInstance();

			pkiva.logic.CertificateValidatorHome cHome = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
			pkiva.logic.CertificateValidator cv = cHome.create();

			auditOper.setPKCS7 ( cms );
			auditOper.setDigest ( digest );

			//System.out.println("SignatureVerifierBean.verify(). Parameters: pkcs7=" + cms + ", digest=" + digest);
			pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verifyDigest(). Parameters: cms=" + cms + ", digest=" + digest);

			CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(new ASN1InputStream(new ByteArrayInputStream(cms)).readObject()));

			CertStore               certs = s.getCertificatesAndCRLs("Collection", "BC");
			SignerInformationStore  signers = s.getSignerInfos();
			Collection              c = signers.getSigners();
			Iterator                it = c.iterator();

			//System.out.println("Cryptographic Message contains "+signers.size()+" signatures");
			pkiva.log.LogManager.getLogger(this.getClass()).info("Cryptographic Message contains "+signers.size()+" signatures");

			while (it.hasNext())
				{
				SignerInformation   signer = (SignerInformation)it.next();

				//compare message digest for every signer

				Attribute mdattr = signer.getSignedAttributes().get(new DERObjectIdentifier("1.2.840.113549.1.9.4"));
				byte[] md = ((DEROctetString)mdattr.getAttrValues().getObjectAt(0)).getOctets();

				if (!MessageDigest.isEqual(md, digest)) throw new Exception("Hash from the DTBS(length "+digest.length+") mismatch with that contained in the CMS(length "+md.length+").");

				//System.out.println("Cryptographic digest for signer "+signers.size()+" correspond with the one from the dtbs.");
				pkiva.log.LogManager.getLogger(this.getClass()).info("Cryptographic digest for signer "+signers.size()+" correspond with the one from the dtbs.");


				//System.out.println("Verifying signature for signer "+signer.getSID());
				pkiva.log.LogManager.getLogger(this.getClass()).info("Verifying signature for signer "+signer.getSID());

				Collection          certCollection = certs.getCertificates(signer.getSID());

				Iterator        certIt = certCollection.iterator();
				X509Certificate cert = (X509Certificate)certIt.next();

				if (signer.verify(cert.getPublicKey(), "BC"))
					{
					//System.out.println("Signature statically verified for signer "+signer.getSID());
					pkiva.log.LogManager.getLogger(this.getClass()).info("Signature statically verified for signer "+signer.getSID());

					CertValidationResponse certificateValidation = cv.checkValidity( new CertValidationRequest ( cert ) );

					if (! certificateValidation.isValid())
						{
						pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is incorrect, certificate chain used to sign is not trusted.");
						audit ( auditOper, false );
						return false;
						}
					}
				else return false;
				}

			pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is correct.");
			audit ( auditOper, true );

			return true;
			}
		catch(Exception e)
			{
            pkiva.log.LogManager.getLogger(this.getClass()).error("Couldn't validate signature due to an internal error." , e );
            audit ( auditOper, e );

            throw new DigitalSignatureValidationErrorException("Couldn't validate signature due to an internal error.", e );
			}

		}

  protected void audit ( SignatureValidation oper, boolean result ) throws AuditingException
  {
    oper.setResult ( result );
    pkiva.log.AuditManager.getAuditer(this.getClass()).audit ( oper );
  }
    
  protected void audit ( SignatureValidation oper, Throwable t )
  {
    try
    {
      oper.setError ( t );
      pkiva.log.AuditManager.getAuditer(this.getClass()).audit ( oper );
    }
    catch ( Throwable ignored )
    {
    }
  }
    
    /** Constructs the bean */
    public SignatureBean() {}    
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

//    /** Verifies signature of a given text with a pkcs7
//     * @param pkcs7 pkcs containing certificates and signature
//     * @param texto Clear text to verify.
//     * @throws DigitalSignatureValidationErrorException In case of error.
//     * @return true if signature validation succeedes, false otherwise.
//     */
//    public boolean verifySignature(byte[] pkcs7, byte[] texto) throws  DigitalSignatureValidationErrorException{
//        SignatureValidation auditOper = new SignatureValidation ();
//        try{
//            auditOper.setPKCS7 ( pkcs7 );
//            if ( texto != null)
//              auditOper.setContent ( texto );
//
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Parameters: pkcs7=" + pkcs7 +  ", texto=" + texto );
//            ServiceLocator svcLoc=ServiceLocator.getInstance();
//            pkiva.logic.SignatureVerifierHome sHome = (pkiva.logic.SignatureVerifierHome)svcLoc.getHome("SignatureVerifier",pkiva.logic.SignatureVerifierHome.class);
//            pkiva.logic.SignatureVerifier sv = sHome.create();
//            boolean signatureValid = texto==null?sv.verify(pkcs7):sv.verify(pkcs7,texto);
//            if(!signatureValid){
//                pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is invalid.");
//                audit ( auditOper, false );
//                return false;
//            }
//            pkiva.logic.CertificateValidatorHome cHome = (pkiva.logic.CertificateValidatorHome)svcLoc.getHome("CertificateValidator",pkiva.logic.CertificateValidatorHome.class);
//            pkiva.logic.CertificateValidator cv = cHome.create();
//            /*boolean certificateValid = cv.checkValidity(pkcs7)==ValidationConstants.GOOD;
//            if(!certificateValid){
//                pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is incorrect, certificate chain used to sign is not trusted.");
//                pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Signature validation gives incorrect result: Signature is incorrect, certificate chain used to sign is not trusted.");
//                return false;
//            }*/
//            CertValidationResponse certificateValidation = cv.checkValidity( new CertValidationRequest ( pkcs7 ) );
//            if ( ! certificateValidation.isValid() )
//            {
//                pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is incorrect, certificate chain used to sign is not trusted.");
//                audit ( auditOper, false );
//                return false;
//            }
//            pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureBean.verifySignature(). Signature is correct.");
//            audit ( auditOper, true );
//            return true;
//        }
//        catch(DigitalSignatureValidationErrorException hex)
//        {
//          pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.verifySignature().DigitalSignatureValidationErrorException " , hex );
//          audit ( auditOper, hex );
//          throw hex;
//        }
////        catch(RemoteException rex){
////            pkiva.log.LogManager.getLogger(this.getClass()).error("SignatureBean.verifySignature().RemoteException " , rex );
////            audit ( auditOper, rex );
////            throw rex;
////        }
//        catch(Exception e){
//            pkiva.log.LogManager.getLogger(this.getClass()).error("Couldn't validate signature due to an internal error." , e );
//            audit ( auditOper, e );
//            throw new DigitalSignatureValidationErrorException("Couldn't validate signature due to an internal error.", e );
//        }
//    }

}
