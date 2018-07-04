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
package pkiva.webservices;

import java.io.FileInputStream;
import java.io.InputStream;

import java.util.Arrays;
import java.util.Enumeration;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;

import pkiva.utils.PKIVAProperties;
import pkiva.webservices.exception.InternalValidatorException;


/**
 * @author rnavalon
 */
public final class SignatureData {

	private static boolean  lazyLoad;
	private static KeyStore keystore;
	
	private static synchronized void init() throws InternalValidatorException  {
		
		try {
			if ( !lazyLoad ) {
				String ksFile;
				String ksPassword;
				
				ksFile     = PKIVAProperties.getProperty("pkiva.signature.ks");
				ksPassword = PKIVAProperties.getProperty("pkiva.signature.ks.password");
				
				if ( ksFile == null ) {
					throw new InternalValidatorException("Missing 'ks' file configuration property");
				}
				
				InputStream is;
				is = Thread.currentThread().getContextClassLoader().getResourceAsStream(ksFile);
				if ( is == null ) {
					try {
						is = new FileInputStream(ksFile);
					} catch( Exception ioe ) {
						throw new InternalValidatorException(ioe);
					}
				}

				keystore = KeyStore.getInstance("PKCS12","BC");
				keystore.load( is , ksPassword == null? null : ksPassword.toCharArray() );
				
				is.close();
				
				lazyLoad = true;
			}
			
		} catch( InternalValidatorException ive ) {
			throw ive;
		} catch( Exception e ) {
			throw new InternalValidatorException (e);
		}
	}
	
	private static void checkInit() throws InternalValidatorException {
		if ( !lazyLoad ) {
			init();
		}
	}
    
    private static String getDefaultAlias() throws InternalValidatorException {
        String aliasName = null;
        
        try {
            Enumeration aliases = keystore.aliases();
        
            if ( aliases != null && aliases.hasMoreElements() ) {
                aliasName = (String)aliases.nextElement();
            
                if ( aliases.hasMoreElements() ) {
                    throw new InternalValidatorException("Invalid keystore. More than one alias found.");
                }
            }
            
        } catch( InternalValidatorException ive ) {
            throw ive;
        } catch( Exception e ) {
            throw new InternalValidatorException (e);
        }
        
        
        if ( aliasName == null ) {
            throw new InternalValidatorException("Invalid keystore. There is no default alias");
        }
        
        return aliasName;
    }
	
	public static String getAlgorithm() throws InternalValidatorException {
		return PKIVAProperties.getProperty("pkiva.signature.algorithm","1.3.14.3.2.26");
	}
	
	public static PrivateKey getPrivateKey() throws InternalValidatorException {
		checkInit();

		try {
			String aliasName;
			String aliasPassword;
			
			aliasName = PKIVAProperties.getProperty("pkiva.signature.alias.name");
			aliasPassword = PKIVAProperties.getProperty("pkiva.signature.alias.password");
			
            if ( aliasName == null ) {
                aliasName = getDefaultAlias();
            }
            
			return (PrivateKey)keystore.getKey(aliasName, aliasPassword==null? null : aliasPassword.toCharArray() );
			
		} catch( Exception e ) {
			throw new InternalValidatorException (e);
		}
	}
	
	public static X509Certificate[] getCertificateChain() throws InternalValidatorException {
		checkInit();
		
		try {
			String aliasName;
			X509Certificate[] certChain = null;
			
			aliasName = PKIVAProperties.getProperty("pkiva.signature.alias.name");
            
            if ( aliasName == null ) {
                aliasName = getDefaultAlias();
            }
			
			Object[] chain = keystore.getCertificateChain(aliasName);
			if ( chain != null ) {
				certChain = new X509Certificate[ chain.length ];
				for( int i = 0; i < chain.length; i++ ) {
					certChain[i] = (X509Certificate)chain[i];
				}
			}
			
			return certChain;
			
		} catch( Exception e ) {
			throw new InternalValidatorException(e);
		}
	}
	
	
	public static X509Certificate getEECertificate(X509Certificate[] certChain) throws InternalValidatorException {
		for (int i=0;i<certChain.length;i++) {
			X509Certificate certificate = (X509Certificate) certChain[i];

			if (certificate.getBasicConstraints() == -1) return certificate;
		}
	
		throw new InternalValidatorException("No end-entity certificate found"); 
	}

	public static CertStore getAllCertificates(X509Certificate[] certChain) throws InternalValidatorException {
		CertStore certstore = null;
	
		try {
			certstore = CertStore.getInstance("Collection",	new CollectionCertStoreParameters(Arrays.asList(certChain)), "BC");
		} catch(Exception e) {
			throw new InternalValidatorException(e);
		}
	
		return certstore;
	}
}
