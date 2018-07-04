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
package pkiva.providers.jce;

import java.security.Provider;
/**
 * This provider registers
 *
 */
public final class PKIVAJCEProvider extends Provider{
    private static String info = "PKI Validation Authority Internal JCE Provider";
    public static String PROVIDER_NAME = "PKIVA_JCE";
    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public PKIVAJCEProvider()
      {
      super(PROVIDER_NAME, 1.0, info);
    
    // CertStore Special Implementation for having an JCA ResourceAdapter
    put("CertStore.ResourceAdapter", "pkiva.providers.jce.certstore.RACertStoreSpi");
    put("CertPathValidator.PKIX_LOOSE", "pkiva.providers.jce.certpath.PolicyCertPathValidatorSpi");
    /*
    * Signature engines 
    */
    put("Signature.SHA1withDSA", "pkiva.providers.jce.DSA");

    put("Alg.Alias.Signature.DSA", "SHA1withDSA");
    put("Alg.Alias.Signature.DSS", "SHA1withDSA");
    put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
    put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
    put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
    put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");
    put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
    put("Alg.Alias.Signature.OID.1.2.840.10040.4.3",
      "SHA1withDSA");
    put("Alg.Alias.Signature.1.2.840.10040.4.3", "SHA1withDSA");
    put("Alg.Alias.Signature.1.3.14.3.2.13", "SHA1withDSA");
    put("Alg.Alias.Signature.1.3.14.3.2.27", "SHA1withDSA");

    /*
    *  Key Pair Generator engines 
    */
    put("KeyPairGenerator.DSA", 
      "pkiva.providers.jce.DSAKeyPairGenerator");
    put("Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1", "DSA");
    put("Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1", "DSA");
    put("Alg.Alias.KeyPairGenerator.1.3.14.3.2.12", "DSA");

    /* 
    * Digest engines 
    */
    put("MessageDigest.MD5", "pkiva.providers.jce.MD5");
    put("MessageDigest.SHA", "pkiva.providers.jce.SHA");

    put("Alg.Alias.MessageDigest.SHA-1", "SHA");
    put("Alg.Alias.MessageDigest.SHA1", "SHA");

    put("MessageDigest.SHA-256", "pkiva.providers.jce.SHA2");
    put("MessageDigest.SHA-384", "pkiva.providers.jce.SHA3");
    put("MessageDigest.SHA-512", "pkiva.providers.jce.SHA5");

    /*
    * Algorithm Parameter Generator engines
    */
    put("AlgorithmParameterGenerator.DSA",
      "pkiva.providers.jce.DSAParameterGenerator");

    /*
    * Algorithm Parameter engines
    */
    put("AlgorithmParameters.DSA",
      "pkiva.providers.jce.DSAParameters");
    put("Alg.Alias.AlgorithmParameters.1.3.14.3.2.12", "DSA");
    put("Alg.Alias.AlgorithmParameters.1.2.840.10040.4.1", "DSA");

    /*
    * Key factories
    */
    put("KeyFactory.DSA", "pkiva.providers.jce.DSAKeyFactory");
    put("Alg.Alias.KeyFactory.1.3.14.3.2.12", "DSA");
    put("Alg.Alias.KeyFactory.1.2.840.10040.4.1", "DSA");

    /*
    * SecureRandom
    */
    put("SecureRandom.SHA1PRNG",
       "pkiva.providers.jce.SecureRandom");

    /*
    * Certificates
    */
    put("CertificateFactory.X.509",
      "pkiva.providers.jce.X509Factory");
    put("Alg.Alias.CertificateFactory.X509", "X.509");

    /*
    * KeyStore
    */
    put("KeyStore.JKS", "pkiva.providers.jce.JavaKeyStore");

    /*
    * CertPathBuilder
    */
    // No exportamos la posibilidad de usar el CertPathBuilder porque no podemos usar el CertPathHelper copiado de SUN
    /*
    put("CertPathBuilder.PKIX",
      "pkiva.providers.jce.certpath.SunCertPathBuilder");
    put("CertPathBuilder.PKIX ValidationAlgorithm", 
      "RFC3280");
    */

    /*
    * CertPathValidator
    */
    put("CertPathValidator.PKIX",
      "pkiva.providers.jce.certpath.PKIXCertPathValidator");
    put("CertPathValidator.PKIX ValidationAlgorithm", 
      "RFC3280");

    /*
    * CertStores
    */
    put("CertStore.LDAP",
      "pkiva.providers.jce.certpath.LDAPCertStore");
    put("CertStore.LDAP LDAPSchema", "RFC2587");
    put("CertStore.Collection",
      "pkiva.providers.jce.certpath.CollectionCertStore");
    put("CertStore.com.sun.security.IndexedCollection",
      "pkiva.providers.jce.certpath.IndexedCollectionCertStore");

    /*
    * KeySize
    */
    put("Signature.SHA1withDSA KeySize", "1024");
    put("KeyPairGenerator.DSA KeySize", "1024");
    put("AlgorithmParameterGenerator.DSA KeySize", "1024");

    /*
    * Implementation type: software or hardware
    */
    put("Signature.SHA1withDSA ImplementedIn", "Software");
    put("KeyPairGenerator.DSA ImplementedIn", "Software");
    put("MessageDigest.MD5 ImplementedIn", "Software");
    put("MessageDigest.SHA ImplementedIn", "Software");
    put("AlgorithmParameterGenerator.DSA ImplementedIn", 
      "Software");
    put("AlgorithmParameters.DSA ImplementedIn", "Software");
    put("KeyFactory.DSA ImplementedIn", "Software");
    put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    put("CertificateFactory.X.509 ImplementedIn", "Software");
    put("KeyStore.JKS ImplementedIn", "Software");
    put("CertPathValidator.PKIX ImplementedIn", "Software");
    put("CertPathBuilder.PKIX ImplementedIn", "Software");
    put("CertStore.LDAP ImplementedIn", "Software");
    put("CertStore.Collection ImplementedIn", "Software");
    put("CertStore.com.sun.security.IndexedCollection ImplementedIn",
      "Software");
    }    
}

