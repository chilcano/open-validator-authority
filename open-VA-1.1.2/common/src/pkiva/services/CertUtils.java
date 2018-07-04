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
package pkiva.services;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import javax.security.auth.x500.X500Principal;

public class CertUtils
{
    /**
     * Checks if given certificate is an End entity
     * @param cert The certificate to check
     * @return true if it is an End entity, false otherwise
     */
    public static boolean isEndEntity(X509Certificate cert){
        return ( cert.getBasicConstraints() == -1 );
    }

    /**
     * Checks that a cert can be used to verify a CRL.
     *
     * @param currCert an X509Certificate to check
     * @return a boolean specifying if the cert is allowed to vouch for the
     * validity of a CRL
     */
    public static boolean certCanSignCrl(X509Certificate currCert) {
        // if the cert doesn't include the key usage ext, or
        // the key usage ext asserts cRLSigning, set CRL_sign_flag to
        // true, otherwise set it to false.
        try {
            boolean [] ku = currCert.getKeyUsage();
            
            if (ku != null) {
            	if ( ku.length < 7 ) {
            		return false;
            	} else {
            		return ku[6]; 
            	}
            	
            } else
                return true;
        } catch (Exception e) {
            pkiva.log.LogManager.getLogger(CertUtils.class).error("certCanSignCRL() unexpected exception",e);
            return false;
        }
    }
    
    /**
     * Checks if given certificate is a TrustAnchor
     * @param cert The certificate to check
     * @return true if it is a TurstAnchor, false otherwise
     */
    public static boolean isTrustAnchor(X509Certificate cert){
        return ( cert.getBasicConstraints() >-1 &&
        cert.getIssuerDN().equals( cert.getSubjectDN() )
        );
    }
    
    /**
     * This method excludes Trust Anchors from given certificate chain.
     * @param certchain The source certificate chain
     * @return A certificate chain where its Trust Anchors have been removed.
     */
    public static X509Certificate[] excludeTrustAnchors(X509Certificate[] certchain) {
        if (certchain == null || certchain.length  == 0)
            return certchain;
        pkiva.log.LogManager.getLogger(CertUtils.class).debug("Excluding TrustAnchors from chain with size: " + certchain.length);
        Vector v = new Vector();
        for (int i=0;i<certchain.length;i++)
            if (isTrustAnchor(certchain[i])){
                pkiva.log.LogManager.getLogger(CertUtils.class).debug("Certificate ["+i+"] is TrustAnchor.");
            }
            else{
                pkiva.log.LogManager.getLogger(CertUtils.class).debug("Certificate ["+i+"] is not TrustAnchor.");
                v.add(certchain[i]);
            }

        X509Certificate[] result = (X509Certificate[]) v.toArray(new X509Certificate[0]);
        pkiva.log.LogManager.getLogger(CertUtils.class).debug("Excluded TrustAnchors, returning chain with size:" + result.length);
        return result;
    }
    
    /**
     * Determine which (if any) trust anchor refers given certificate,
     *
     * @param trustAnchors All available trusted anchors
     * @param cert certificate to determine which trusted anchor signs it.
     * @return returns the trust anchor or null if nothing matches
     */
    public static X509Certificate getTrustAnchor(Collection trustAnchors, X509Certificate cert ){
        pkiva.log.LogManager.getLogger(CertUtils.class).debug("Looking for trustAnchor that signs cert with SN: "+cert.getSerialNumber());
        for(Iterator it = trustAnchors.iterator();it.hasNext();){
            TrustAnchor anchor = (TrustAnchor)it.next();
            X509Certificate trustedCert = anchor.getTrustedCert();
            // the subject of the trusted cert should match the
            // issuer of the first cert in the certpath
            X500Principal trustedSubject = trustedCert.getSubjectX500Principal();
            if (trustedSubject.equals(cert.getIssuerX500Principal())) {
                pkiva.log.LogManager.getLogger(CertUtils.class).debug("Found suitable trusted anchor for given chain.");
                return trustedCert;
            }
        }
        pkiva.log.LogManager.getLogger(CertUtils.class).error("Cannot determine trusted anchor for given chain.");
        return null;
    }

  /**
   * Returns the fingerPrint (digest using SHA1)
   *
   * @param cert Certificate to calculate digest from
   * @return fingerprint as byte[]
   */
  public static byte[] getFingerPrint ( X509Certificate cert ) throws java.security.cert.CertificateEncodingException, java.security.NoSuchAlgorithmException
  {
      byte[] data = cert.getEncoded();

      return MessageDigest.getInstance("SHA1").digest(data);
  }

  /**
   * Returns the fingerPrint (digest using SHA1) as a Hexadecimal String 
   *
   * @param cert Certificate to calculate digest from
   * @return fingerprint as hexadecimal String 
   */
  public static String getFingerPrintAsHexa ( X509Certificate cert ) throws java.security.cert.CertificateEncodingException, java.security.NoSuchAlgorithmException
  {
      return toHexString( getFingerPrint (cert) );
  }

	private static String toHexString(byte abyte0[])
  {
    StringBuffer stringbuffer = new StringBuffer();
         int i = abyte0.length;
         for(int j = 0; j < i; j++)
           {
           byte2hex(abyte0[j], stringbuffer);
             if(j < i - 1)
               stringbuffer.append(":");
         }
         return stringbuffer.toString();
   }
     
   private static void byte2hex(byte byte0, StringBuffer stringbuffer)
   {
   char ac[] = {
     '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
       'A', 'B', 'C', 'D', 'E', 'F'
     };
       int i = (byte0 & 0xf0) >> 4;
       int j = byte0 & 0xf;
       stringbuffer.append(ac[i]);
       stringbuffer.append(ac[j]);
  }

  public static String getSerialNumberAsHexa (  X509Certificate cert )
  {
    String snInt = cert.getSerialNumber().toString(16);
    StringBuffer stringbuffer = new StringBuffer();
    int i = snInt.length();
    for(int j = 0; j < i; j++)
    {
      stringbuffer.append( snInt.charAt(j) );
      if ( (j % 2 == 1) && (j < i - 1) )
        stringbuffer.append(":");
    }
    return stringbuffer.toString();

  }

  public static X509Certificate getCertFromEncoded ( byte[] enc ) throws java.security.cert.CertificateException
  {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    return (X509Certificate)cf.generateCertificate(bais);
  }
}
