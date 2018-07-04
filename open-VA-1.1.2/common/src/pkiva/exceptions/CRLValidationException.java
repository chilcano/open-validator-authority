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
package pkiva.exceptions;

import java.security.cert.CertPathValidatorException;
/**
* Class: CRLValidationException:
*
* Exception raised when there's an error validating a certificate chain via CRL.
*/

public class CRLValidationException extends RevocationCheckingException
{
	/**
 	* CRLValidationException class constructor
 	*/
    public CRLValidationException(){
		super();
	}
    
	/**
 	* CRLValidationException class constructor
 	* @param message describes excepcion's cause
 	*/
    public CRLValidationException(String message){
		super(message);
	}
    
	/**
 	* CRLValidationException class constructor
 	* @param message describes excepcion's cause
 	* @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
 	*/
    public CRLValidationException(String message, Throwable cause){
		super(message, cause);
	}
    
	/**
 	* CRLValidationException class constructor
 	* @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
 	*/
    public CRLValidationException(Throwable cause){
		super(cause);
	}
    
}
