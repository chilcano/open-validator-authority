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
package pkiva;


import java.util.Hashtable;

import java.security.cert.X509Certificate;

import javax.ejb.CreateException;
import javax.ejb.RemoveException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;

import java.rmi.RemoteException;

import pkiva.logic.services.Certificate;
import pkiva.logic.services.CertificateLocal;
import pkiva.logic.services.CertificateHome;
import pkiva.logic.services.CertificateLocalHome;
import pkiva.logic.services.Signature;
import pkiva.logic.services.SignatureLocal;
import pkiva.logic.services.SignatureHome;
import pkiva.logic.services.SignatureLocalHome;
import pkiva.utils.PKIVAProperties;
import pkiva.validation.CertValidationRequest;
import pkiva.validation.CertValidationResponse;
import pkiva.webservices.exception.InternalValidatorException;
import pkiva.webservices.exception.ValidatorException;
import pkiva.exceptions.DigitalSignatureValidationErrorException;


/**
 * @author rnavalon
 */
public class Validator {

	private Context createJndiContext() throws NamingException {
		
		Context jndiContext;
		Hashtable env;
		
		env = new Hashtable();
		
		jndiContext = new InitialContext(env);

		return jndiContext;
	}

	private CertValidationResponse validateCertificate( CertValidationRequest request )
		throws CreateException , NamingException , RemoteException , RemoveException {
		
		CertValidationResponse response = null;
		
		Context jndiContext;
		String  lookupName = PKIVAProperties.getProperty("validator.certificate.lookup.name");
		String  lookupMode = PKIVAProperties.getProperty("validator.certificate.lookup.mode","remote");
		
		if ( lookupName == null ) {
			throw new CreateException("Missing lookup name for Certificate service");
		}
		
		jndiContext = createJndiContext();
		
		Object ref = jndiContext.lookup( lookupName );
		if ( lookupMode.equalsIgnoreCase("remote") ) {
			CertificateHome home;
			Certificate     certificate;
			
			home = (CertificateHome)PortableRemoteObject.narrow( ref , CertificateHome.class );
			
			certificate = home.create();
			try {
				response = certificate.isValid( request );
			} finally {
				certificate.remove();
			}
			
		} else if ( lookupMode.equalsIgnoreCase("local") ) {
			CertificateLocalHome home;
			CertificateLocal     certificate;
			
			home = (CertificateLocalHome)ref;
			
			certificate = home.create();
			try {
				response = certificate.isValid( request );
			} finally {
				certificate.remove();
			}
			
		} else {
			throw new CreateException("Only remote or local mode for ejb are allowed");
		}		
		
		return response;
	}
	
	private boolean validateSignature( byte[] pkcs7 , byte[] data )
		throws CreateException , NamingException , RemoteException , RemoveException , DigitalSignatureValidationErrorException {
		
		boolean valid = false;
		
		Context jndiContext;
		String  lookupName = PKIVAProperties.getProperty("validator.signature.lookup.name");
		String  lookupMode = PKIVAProperties.getProperty("validator.signature.lookup.mode","remote");
			
		if ( lookupName == null ) {
			throw new CreateException("Missing lookup name for Signature service");
		}
			
		jndiContext = createJndiContext();

		Object ref = jndiContext.lookup( lookupName );
		if ( lookupMode.equalsIgnoreCase("remote") ) {
			SignatureHome home;
			Signature     signature;
			
			home = (SignatureHome)PortableRemoteObject.narrow( ref , SignatureHome.class );
			signature = home.create();

			if ( data == null ) {
				valid = signature.verifySignature(pkcs7);
			} else {
				valid = signature.verifySignature( pkcs7 , data );
			}
			
		} else if ( lookupMode.equalsIgnoreCase("local") ) {
			SignatureLocalHome home;
			SignatureLocal     signature;
			
			home = (SignatureLocalHome)ref;
			signature = home.create();

			if ( data == null ) {
				valid = signature.verifySignature(pkcs7);
			} else {
				valid = signature.verifySignature( pkcs7 , data );
			}
			
		} else {
			throw new CreateException("Only remote or local mode for ejb are allowed");
		}
			
		return valid;
	}
	
	public void checkValidCertificate( X509Certificate cert ) throws ValidatorException {
		try {
			CertValidationRequest request;
			CertValidationResponse response;
				
			request  = new CertValidationRequest(cert);
			response = validateCertificate( request );
				
			switch( response.getState() ) {
			case CertValidationResponse.UNKNOWN:
				throw new ValidatorException( ValidatorException.EXPIRED_CRLS );
					
			case CertValidationResponse.GOOD:
				break;
					
			case CertValidationResponse.REVOKED:
				throw new ValidatorException( ValidatorException.REVOQUED_CERTIFICATE );
					
			case CertValidationResponse.INVALID_POLICY:
			case CertValidationResponse.SUSPENDED:
				throw new ValidatorException( ValidatorException.SUSPENDED_CERTIFICATE );
				
			case CertValidationResponse.EXPIRED:
				throw new ValidatorException( ValidatorException.EXPIRED_CERTIFICATE );
					
			case CertValidationResponse.INVALID_CERTCHAIN:
			case CertValidationResponse.CERTCHAIN_NOT_FOUND:
				throw new ValidatorException( ValidatorException.UNKNOWN_CERTIFICATE );
					
			case CertValidationResponse.NOT_YET_VALID:
				throw new ValidatorException( ValidatorException.NOT_YET_VALID );
					
			default:
				throw new InternalValidatorException("Unknown response code in validator component");
			}
			
		} catch( NamingException ne ) {
			throw new InternalValidatorException( ne );
		} catch( RemoteException re ) {
			throw new InternalValidatorException( re );
		} catch( CreateException ce ) {
			throw new InternalValidatorException( ce );
		} catch( RemoveException re ) {
			throw new InternalValidatorException( re );
		}
	}
	
	public void checkValidSignature( byte[] pkcs7 ) throws ValidatorException {
		try {
			if ( !validateSignature(pkcs7,null) ) {
				throw new ValidatorException( ValidatorException.INVALID_SIGNATURE );
			}
			
		} catch( DigitalSignatureValidationErrorException dsve ) {
			throw new InternalValidatorException( dsve );
		}  catch( NamingException ne ) {
			throw new InternalValidatorException( ne );
		} catch( RemoteException re ) {
			throw new InternalValidatorException( re );
		} catch( CreateException ce ) {
			throw new InternalValidatorException( ce );
		} catch( RemoveException re ) {
			throw new InternalValidatorException( re );
		}
	}
	
	public void checkValidSignature( byte[] pkcs7 , byte[] data ) throws ValidatorException {
		try {
			if ( !validateSignature(pkcs7,data) ) {
				throw new ValidatorException( ValidatorException.INVALID_SIGNATURE );
			}
			
		} catch( DigitalSignatureValidationErrorException dsve ) {
			throw new InternalValidatorException( dsve );
		}  catch( NamingException ne ) {
			throw new InternalValidatorException( ne );
		} catch( RemoteException re ) {
			throw new InternalValidatorException( re );
		} catch( CreateException ce ) {
			throw new InternalValidatorException( ce );
		} catch( RemoveException re ) {
			throw new InternalValidatorException( re );
		}
	}	
}
