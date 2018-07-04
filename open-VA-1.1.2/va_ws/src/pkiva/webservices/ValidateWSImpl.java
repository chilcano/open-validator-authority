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


import java.util.Iterator;
import java.util.List;

import java.rmi.RemoteException;

import java.security.Security;
import java.security.cert.X509Certificate;

import pkiva.CertificateFields;
import pkiva.Validator;
import pkiva.utils.Log;
import pkiva.utils.PKIVAProperties;
import pkiva.webservices.Request;
import pkiva.webservices.Response;
import pkiva.webservices.exception.InternalValidatorException;
import pkiva.webservices.exception.ValidatorException;


/**
 * @author rnavalon
 */
public class ValidateWSImpl implements ValidateWS {

	static {
        int idx;
        
        idx = Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        if ( idx != -1 ) {
            Log.info("Added BouncyCastle security provider (" + idx + ")");
        }
	}
	
	private void doValidate( Request request ) throws ValidatorException {
		Validator validator;
		
		validator = new Validator();
		
		switch( request.getOption() ) {
		case Request.RAWX509CERTIFICATE:
			Log.info("Validate RAWX509CERTIFICATE");
			validator.checkValidCertificate( request.getCertificate() );
			break;
			
		case Request.PKCS7SIGNATURE:
			Log.info("Validate PKCS7SIGNATURE");
			validator.checkValidSignature( request.getRawSignedDocument() );
			break;
			
		case Request.SIGNEDDETACHEDDOC:
			Log.info("Validate SIGNEDDETACHEDDOC");
			validator.checkValidSignature( request.getRawSignature() , request.getRawDocument());
			break;
			
			default:
				throw new InternalValidatorException("Unknonw option type");
		}
	}
	
	private void doFields( Request request , Response response , CertificateFields fields ) throws ValidatorException {
		
		if ( request.isFields() ) {
			response.setFields( fields );
		}
	}
	
	/*
	 * @see pkiva.ValidateWS#validate(java.lang.String)
	 */
	public String validate(String xmlIn ) throws RemoteException {
        long start , end;
		Response response;
		Request request;
		
        
        start = System.currentTimeMillis();
        try {
            
            Log.info("Received request: " + xmlIn );
            response = new Response();
            
            try {
                
                request = new Request(xmlIn.trim());
                
                try {
                    if ( request.getOption() == Request.UNDEFINED ) {
                        
                        throw new InternalValidatorException("Unrecognized token");
                        
                    } else {
                        
                        Log.info( "Executing request (Type = " + request.getOption() + ")" );

                        response.setValue( Response.SUCCESS );
                        
                        try {
                            CertificateFields fields;
                            X509Certificate cert;
                            
                            cert = request.getCertificate();
                            Log.debug("Certificate in request:\r\n" + cert );
                            
                            fields = new CertificateFields( request.getCertificate() );
                            Log.debug("Certificate fields:\r\n" + fields );
                            
                            Log.info("Executing validate action");
                            doValidate(request);
                            
                            Log.info("Setting response fields");
                            doFields(request,response, fields);
                            
                            Log.info("Certificate is valid");
                            response.setStatus( Response.VALID );
                            
                        } catch( ValidatorException ve ) {
                            response.setStatus( Response.INVALID );
                            response.setStatusReason( ve.getErrCode() );
                            response.setStatusReasonDescription( ve.getMessage() );
                            Log.warning( "Error validating certificate" , ve );
                            
                        } catch( Exception e ) {
                            response.setStatusReason( ValidatorException.INTERNAL_ERROR );
                            response.setStatusReasonDescription( e.getMessage() );
                            Log.critical( "Unknown error validating certificate" , e );
                        }
                    }
                    
                } catch( InternalValidatorException ive ) {
                    response.setValue( Response.FAILURE );
                    response.setCodeError( ive.getErrDescription() );
                    Log.warning( "Error parsing request" , ive );
                }
                
            } catch( InternalValidatorException ive ) {
                response.setValue( Response.REFUSED );
                response.setCodeError( ive.getErrDescription() );
                Log.warning( "Error reading input parameters" , ive );
            }
            
            try {
                String xmlOut = response.toXMLString();
                
                Log.info("Sending response: " + xmlOut );
                return xmlOut;
                
            } catch( Exception e ) {
                Log.error( "Error sending response" , e );
                throw new RemoteException( "Unable to send response" , e );   
            }
            
        } finally {
            end = System.currentTimeMillis();
            Log.info( "Elapsed time: " + (end - start) + " ms." );
        }
	}
}
