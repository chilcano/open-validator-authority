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

import pkiva.validation.ValidationObject;
/**
* Class: UnknownCertificateChainRevocationStatusException:
*
* Exception raised on unknown status found when validating a Certificate chain.
*/
public class UnknownCertificateChainRevocationStatusException extends java.security.cert.CertPathValidatorException
{
  protected ValidationObject valObj = null;

	/**
 	* UnknownCertificateChainRevocationStatusException class constructor
 	*/
    public UnknownCertificateChainRevocationStatusException(){
		super();
	}
    
	/**
 	* UnknownCertificateChainRevocationStatusException class constructor
 	* @param message describes excepcion's cause
 	*/
    public UnknownCertificateChainRevocationStatusException(String message){
		super(message);
	}
    
	/**
 	* UnknownCertificateChainRevocationStatusException class constructor
 	* @param message describes excepcion's cause
 	* @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
 	*/
    public UnknownCertificateChainRevocationStatusException(String message, Throwable cause){
		super(message, cause);
	}
    
	/**
 	* UnknownCertificateChainRevocationStatusException class constructor
 	* @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
 	*/
    public UnknownCertificateChainRevocationStatusException(Throwable cause){
		super(cause);
	}

    /** Getter for property valObj.
     * @return Value of property valObj.
     *
     */
    public ValidationObject getValidationObject()
    {
      return valObj;
    }    

    /** Setter for property valObj.
     * @param valObj New value of property valObj.
     *
     */
    public void setValidationObject(ValidationObject valObj)
    {
      this.valObj = valObj;
    }
    
}
