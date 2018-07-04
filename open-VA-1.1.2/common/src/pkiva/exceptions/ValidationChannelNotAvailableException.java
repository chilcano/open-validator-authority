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

/**
* Class: ValidationChannelNotAvailableException:
*
* Exception raised when trying to validate a certificate using a non existing 
* channel or a channel not accepted for the certificate, according to the configured 
* certificate validation policies.
*/

public class ValidationChannelNotAvailableException extends BaseException{
	/**
 	* ValidationChannelNotAvailableException class constructor
 	* @param message describes excepcion's cause
 	*/
	public ValidationChannelNotAvailableException (String message)	{
		super(message);
	}
}
