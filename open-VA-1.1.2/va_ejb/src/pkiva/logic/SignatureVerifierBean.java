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

/**
 * Class: SignatureVerifierBean:
 *
 * Session EJB que valida una firma digital recibida por parametro.
 */
import pkiva.exceptions.DigitalSignatureValidationErrorException;

import java.util.*;
import java.io.*;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;

import javax.rmi.PortableRemoteObject;
import java.rmi.RemoteException;

import javax.ejb.*;

import java.security.*;
import java.security.cert.*;

import org.bouncycastle.jce.PKCS7SignedData;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
//import org.bouncycastle.cms.*;


import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.SignedData;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;

public class SignatureVerifierBean   implements SessionBean {
    private SessionContext context;
    
    
    /**
     * Funcion encargada de validar la firma digital si el mensaje original esta inlcuído en el PKCS7.
     * @param pkcs7, pkcs7 a validar en formato byte[].
     * @return boolean, true = firma digital valida. false = firma digital erronea.
     * @exception DigitalSignatureValidationErrorException
     */
    public boolean verify(byte[] pkcs7) throws  RemoteException, DigitalSignatureValidationErrorException {
        pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verify(). Parameters: pkcs7=" + pkcs7);
        return verify(pkcs7,null);
    }

    /**
     * Funcion encargada de validar la firma digital.
     * @param pkcs7, pkcs7 a validar en formato byte[].
     * @param texto, texto firmado en el pkcs7 (solo incluirlo en el caso en el que el pkcs7 no lo contenga ya).
     * @return boolean, true = firma digital valida. false = firma digital erronea.
     * @exception DigitalSignatureValidationErrorException
     */
    public boolean verify(byte[] pkcs7, byte[] texto) throws  RemoteException, DigitalSignatureValidationErrorException {
        pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verify(). Parameters: pkcs7=" + pkcs7 + ", texto=" + texto);
        try {
            byte[] cleartext;
            if (texto==null){
            	CMSSignedData sd = new CMSSignedData(pkcs7);
            	cleartext = (byte[])sd.getSignedContent().getContent();
                if (cleartext==null)
                    throw new DigitalSignatureValidationErrorException("Original clear text whose corresponding to the signature being verified was not provided and is not inlcuded in the PKCS7.");
            }
            else
                cleartext=texto;

            
            ContentInfo cInfo = ContentInfo.getInstance(new ASN1InputStream(new ByteArrayInputStream(pkcs7)).readObject());

            SignedData sigData = SignedData.getInstance(cInfo.getContent());
            DERObjectIdentifier contentType = sigData.getEncapContentInfo().getContentType();
            CMSSignedData cmsSigData = new CMSSignedData(cInfo);

            CertStore certs = cmsSigData.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = cmsSigData.getSignerInfos();
            Collection              signersCol = signers.getSigners();
            Iterator                signersColIter = signersCol.iterator();

            int i = 0;
            while (signersColIter.hasNext())
            {
              SignerInfo info = SignerInfo.getInstance( sigData.getSignerInfos().getObjectAt(i++) );
              ASN1Set signedAtts = info.getAuthenticatedAttributes();

              SignerInformation signer = (SignerInformation)signersColIter.next();
              AttributeTable signerAttTable = signer.getSignedAttributes();

              Collection certCollection = certs.getCertificates(signer.getSID());
              Iterator certIt = certCollection.iterator();
              X509Certificate cert = (X509Certificate)certIt.next();

              checkSignatureDate ( signerAttTable, cert );

              Signature signature = Signature.getInstance( getDigestAlgName(signer) + "with" + getEncryptionAlgName(signer), "BC");
              MessageDigest digest = MessageDigest.getInstance( getDigestAlgName(signer), "BC");

              CMSProcessable content = new CMSProcessableByteArray(cleartext);
              if ( signedAtts == null)
              {
                pkiva.log.LogManager.getLogger(this.getClass()).info("Sign Verification with no signed content, must sign content");
                if ( ! doVerify( signer, signature, cert.getPublicKey(), content ) )
                  return false;
                pkiva.log.LogManager.getLogger(this.getClass()).info("Successful signature verification");
              }
              else
              {
                pkiva.log.LogManager.getLogger(this.getClass()).info("Sign Verification with signed content, will verify digest");
                //digest
                content.write( new DigOutputStream(digest) );
                byte[]  hash = digest.digest();

                if ( ! doVerify( signer, hash, signature, cert.getPublicKey(), signerAttTable, contentType, signedAtts) )
                  return false;
                pkiva.log.LogManager.getLogger(this.getClass()).info("Successful signature verification");
              }
            }
          return true;
        }
        catch (CMSException ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Wrong signature verification. Error cause:", ex);
            return false;
        }
        catch (NoSuchAlgorithmException ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("PKCS7 with unknown digestAlgorithm or signatureAlgorithm", ex);
            return false;
        }
        catch (Exception ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Internal error in signature verification.", ex);
            throw new DigitalSignatureValidationErrorException(ex.getMessage(), ex);
        }
    }

    
    /**
     * Funcion encargada de validar la firma digital.
     * @param pkcs7, pkcs7 a validar en formato byte[].
     * @param digest, hash del texto firmado en el pkcs7
     * @return boolean, true = firma digital valida. false = firma digital erronea.
     * @exception DigitalSignatureValidationErrorException
     */
    public boolean verifyDigest(byte[] pkcs7, byte[] digestBytes ) throws  RemoteException,DigitalSignatureValidationErrorException 
    {
      try
      {
            pkiva.log.LogManager.getLogger(this.getClass()).debug("SignatureVerifierBean.verifyDigest(). Parameters: pkcs7=" + pkcs7 + ", digestBytes=" + digestBytes);
            ContentInfo cInfo = ContentInfo.getInstance(new ASN1InputStream(new ByteArrayInputStream(pkcs7)).readObject());

            SignedData sigData = SignedData.getInstance(cInfo.getContent());
            DERObjectIdentifier contentType = sigData.getEncapContentInfo().getContentType();
            CMSSignedData cmsSigData = new CMSSignedData(cInfo);

            CertStore certs = cmsSigData.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = cmsSigData.getSignerInfos();
            Collection              signersCol = signers.getSigners();
            Iterator                signersColIter = signersCol.iterator();

            int i = 0;
            while (signersColIter.hasNext())
            {
              SignerInfo info = SignerInfo.getInstance( sigData.getSignerInfos().getObjectAt(i++) );
              ASN1Set signedAtts = info.getAuthenticatedAttributes();

              SignerInformation signer = (SignerInformation)signersColIter.next();
              AttributeTable signerAttTable = signer.getSignedAttributes();

              Collection certCollection = certs.getCertificates(signer.getSID());
              Iterator certIt = certCollection.iterator();
              X509Certificate cert = (X509Certificate)certIt.next();

              checkSignatureDate ( signerAttTable, cert );

              Signature signature = Signature.getInstance( getDigestAlgName(signer) + "with" + getEncryptionAlgName(signer), "BC");
              MessageDigest digest = MessageDigest.getInstance( getDigestAlgName(signer), "BC");

              if ( ! doVerify( signer, digestBytes, signature, cert.getPublicKey(), signerAttTable, contentType, signedAtts) )
                return false;
            }
          return true;
        }
        catch (CMSException ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).info("Wrong signature verification. Error cause:", ex);
            return false;
        }
        catch (NoSuchAlgorithmException ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("PKCS7 with unknown digestAlgorithm or signatureAlgorithm", ex);
            return false;
        }
        catch (Exception ex) {
            pkiva.log.LogManager.getLogger(this.getClass()).error("Internal error in signature verification.", ex);
            throw new DigitalSignatureValidationErrorException(ex.getMessage(), ex);
        }

    }



    protected void checkSignatureDate ( AttributeTable attr, X509Certificate cert ) throws CertificateException
    {
      if (attr != null)
      {
          Attribute t = attr.get(CMSAttributes.signingTime);

          if (t != null)
          {
              Time time = Time.getInstance( t.getAttrValues().getObjectAt(0) );

              cert.checkValidity(time.getDate());
          }
      }
    }

    protected boolean doVerify(
        SignerInformation sigInfo, 
        byte[]  hash,
        Signature       signature,
        PublicKey       key,
        AttributeTable  signedAttrTable, 
        DERObjectIdentifier contentType, 
        ASN1Set signedAtts
      )
        throws CMSException
    {
        try
        {
            signature.initVerify(key);
            
            if (signedAttrTable == null)
            {
                throw new IllegalArgumentException("Can't check digest with no signed data in pkcs7.");
            }
            else
            {
                Attribute dig = signedAttrTable.get(
                                CMSAttributes.messageDigest);
                Attribute type = signedAttrTable.get(
                                CMSAttributes.contentType);

                if (dig == null)
                {
                    throw new SignatureException("no hash for content found in signed attributes");
                }

                if (type == null)
                {
                    throw new SignatureException("no content type id found in signed attributes");
                }

                byte[]  signedHash = ((ASN1OctetString)dig.getAttrValues().getObjectAt(0)).getOctets();

                if (!MessageDigest.isEqual(hash, signedHash))
                {
                    throw new SignatureException("content hash found in signed attributes different");
                }

                DERObjectIdentifier  typeOID = (DERObjectIdentifier)type.getAttrValues().getObjectAt(0);

                if (!typeOID.equals(contentType))
                {
                    throw new SignatureException("contentType in signed attributes different");
                }

                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                DEROutputStream dOut = new DEROutputStream(bOut);

                dOut.writeObject( signedAtts ); 

                dOut.close();

                signature.update(bOut.toByteArray());
            }

            return signature.verify(sigInfo.getSignature());
        }
        catch (InvalidKeyException e)
        {
            throw (CMSException) new CMSException( "key not appropriate to signature in message." ).initCause(e);
        }
        catch (IOException e)
        {
            throw (CMSException) new CMSException( "can't process mime object to create signature." ).initCause(e);
        }
        catch (SignatureException e)
        {
            throw (CMSException) new CMSException( "invalid signature format in message." ).initCause(e);
        }
        catch (IllegalArgumentException e)
        {
            throw (CMSException) new CMSException( "invalid signature format in message." ).initCause(e);
        }
        catch (Exception e)
        {
            throw (CMSException) new CMSException( e.getMessage() ).initCause(e);
        }
    }


    protected boolean doVerify(SignerInformation sigInfo, Signature signature, PublicKey key, CMSProcessable content ) throws CMSException
    {
        try
        {
            signature.initVerify(key);
            
            if (content == null)
            {
              throw new IllegalArgumentException("no content specified for signature verification.");
            }

            content.write( new SigOutputStream(signature));

            return signature.verify(sigInfo.getSignature());
        }
        catch (InvalidKeyException e)
        {
            throw (CMSException) new CMSException( "key not appropriate to signature in message." ).initCause(e);
        }
        catch (IOException e)
        {
            throw (CMSException) new CMSException( "can't process mime object to create signature." ).initCause(e);
        }
        catch (SignatureException e)
        {
            throw (CMSException) new CMSException( "invalid signature format in message." ).initCause(e);
        }
        catch (IllegalArgumentException e)
        {
            throw (CMSException) new CMSException( "invalid signature format in message." ).initCause(e);
        }
        catch (Exception e)
        {
            throw (CMSException) new CMSException( e.getMessage() ).initCause(e);
        }
    }


    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    protected String getEncryptionAlgName(SignerInformation sigInfo)
    {
        String  encryptionAlgOID = sigInfo.getEncryptionAlgOID();
        
        if (CMSSignedDataGenerator.ENCRYPTION_DSA.equals(encryptionAlgOID))
        {
            return "DSA";
        }
        else if ("1.2.840.10040.4.1".equals(encryptionAlgOID))
        {
            return "DSA";
        }
        else if (CMSSignedDataGenerator.ENCRYPTION_RSA.equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if ("1.2.840.113549.1.1.5".equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else
        {
            return encryptionAlgOID;            
        }
    }    


    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    protected String getDigestAlgName(SignerInformation sigInfo)
    {
        String  digestAlgOID = sigInfo.getDigestAlgOID();
        
        if (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlgOID))
        {
            return "MD5";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA1.equals(digestAlgOID))
        {
            return "SHA1";
        }
        else
        {
            return digestAlgOID;            
        }
    }
    
     static class DigOutputStream
        extends OutputStream
    {
        MessageDigest   dig;

       public DigOutputStream(
            MessageDigest   dig)
        {
            this.dig = dig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            dig.update(b, off, len);
        }

        public void write(
            int b)
            throws IOException
        {
            dig.update((byte)b);
        }
    }

    static class SigOutputStream
        extends OutputStream
    {
        Signature   sig;

        public SigOutputStream(
            Signature   sig)
        {
            this.sig = sig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            try
            {
                sig.update(b, off, len);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }

        public void write(
            int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }
    }

    public SignatureVerifierBean() {}
    
    public void ejbCreate() throws CreateException {}
    
    public void setSessionContext(SessionContext theContext) {
        this.context = theContext;
    }
    
    public void ejbActivate() {}
    
    public void ejbPassivate() {}
    
    public void ejbRemove() {}
}
