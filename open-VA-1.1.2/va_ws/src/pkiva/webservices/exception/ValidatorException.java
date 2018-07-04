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
package pkiva.webservices.exception;

/**
 * Excepcion en el validador.
 * 
 * @author rnavalon
 */
public class ValidatorException extends Exception {
	
	private static final long serialVersionUID = 1L;

	
	public static final int UNKNOWN_CERTIFICATE		= 2;
	public static final int INVALID_CERTIFICATE		= 3;
	public static final int NOT_ALLOWED_CERTIFICATE	= 4;
	public static final int SUSPENDED_CERTIFICATE	= 5;
	public static final int EXPIRED_CERTIFICATE		= 6;
	public static final int REVOQUED_CERTIFICATE	= 7;
	public static final int INVALID_SIGNATURE		= 8;
	public static final int EXPIRED_CRLS			= 9;
	public static final int WRONG_CERTIFICATE		= 10;
	public static final int NOT_YET_VALID			= 11;
	public static final int INTERNAL_ERROR			= 50;
	

	private int errCode;
	private String errDescription;
	
	
	public ValidatorException() {
	}
	
	public ValidatorException( int errCode ) {
		super( String.valueOf(errCode) );
		
		this.errCode = errCode;
	}
	
	public ValidatorException( int errCode , String errDescription ) {
		super( errCode + " (" + errDescription + ")" );
		
		this.errCode = errCode;
		this.errDescription = errDescription;
	}
	
	public ValidatorException( int errCode , Throwable cause ) {
		super( String.valueOf(errCode) , cause );
		
		this.errCode = errCode;
	}
	
	public int getErrCode() { return this.errCode; }
	public String getErrDescription() { return this.errDescription; }
	
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		
		sb.append( "Error Code: " );
		sb.append( this.errCode );
		
		if ( this.errDescription != null ) {
			sb.append( " (" );
			sb.append( this.errDescription );
			sb.append( ")" );
		}
		
		if ( getCause() != null ) {
			sb.append( " , " );
			sb.append( getCause().toString() );
		}
		
		return sb.toString();
	}
}
