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
package pkiva.validation;


import java.security.cert.*;
import java.security.*;
import java.util.*;
import java.io.*;

import pkiva.ldap.PKIXDistributionPoint;

/** This class holds information to process a Certificate Validation Request
 * @author diriarte
 */
public class CertValidationRequest implements java.io.Serializable
{
  /** Validation Channel Parameter Value : CRL Revocation Channel */  
  public static final String CRL = PKIXDistributionPoint.PKIXCRLDP;
  /** Validation Channel Parameter Value : OCSP Revocation Channel */  
  public static final String OCSP = PKIXDistributionPoint.PKIXOCSPDP;
  
  /** Certificate Policies Parameter Name. Value must be a Set of Strings with the
   * policies
   */  
  public static final Integer POLICIES = new Integer ( 1 );
  /** Validation Channel Parameter Name. Value must be one of the constants */  
  public static final Integer VALIDATION_CHANNEL = new Integer ( 2 );
  /** Info Requested Parameter Name. Value must be Boolean */  
  public static final Integer REQUEST_INFO = new Integer ( 3 );

  private static final int CERT = 1;
  private static final int CHAIN = 2;
  private static final int PKCS7 = 3;

  protected X509Certificate cert;
  protected X509Certificate[] chain;
  protected byte[] pkcs7;
  
  protected Hashtable parameters;

  protected int certObject;
  

  protected CertValidationRequest( )
  {
    parameters = new Hashtable();
  }
  
  /** Creates a new instance of CertValidationRequest.
   * @param certificate Certificate to be validated
   */  
  public CertValidationRequest(X509Certificate certificate)
  {
    this();
    this.cert = certificate;
    this.certObject = CERT;
  }
  
  /** Creates a new instance of CertValidationRequest.
   * @param certChain Certificate Chain to be validated
   */  
  public CertValidationRequest(X509Certificate[] certChain)
  {
    this();
    this.chain = certChain;
    this.certObject = CHAIN;
  }
  
  /** Creates a new instance of CertValidationRequest.
   * @param pkcs7Chain Certificate Chain in pkcs7 format to be validated
   */  
  public CertValidationRequest(byte[] pkcs7Chain)
  {
    this();
    this.pkcs7 = pkcs7Chain;
    this.certObject = PKCS7;
  }
  
  /** Gets one parameter from the request. See fields for names and values
   * @param key Integer with the constant meaning parameter name
   * @return Object bound to the parameter name, if any
   */  
  public Object getParameter ( Integer key )
  {
    return parameters.get ( key );
  }
  
  /** Adds one parameter to the request. See fields for names and values
   * @param key Integer with the constant meaning parameter name
   * @param value Object to be bind to the parameter name
   */  
  public void addParameter ( Integer key, Object value )
  {
    parameters.put ( key, value );
  }
  
  /** */  
  public String toString ( )
  {
    return parameters.toString();
  }

  /** Getter for property cert.
   * @return Value of property cert.
   *
   */
  public java.security.cert.X509Certificate getCert()
  {
    return cert;
  }
  
  /** Getter for property chain.
   * @return Value of property chain.
   *
   */
  public java.security.cert.X509Certificate[] getChain()
  {
    return this.chain;
  }
  
  /** Getter for property pkcs7.
   * @return Value of property pkcs7.
   *
   */
  public byte[] getPkcs7()
  {
    return this.pkcs7;
  }

 private void writeObject(java.io.ObjectOutputStream out)
     throws IOException
  {
    out.writeInt ( this.certObject );
    switch ( this.certObject )
    {
      case CERT:     
        out.writeObject ( this.cert );
        break;

      case CHAIN:     
        out.writeObject ( this.chain );
        break;

      case PKCS7:     
        out.writeObject ( this.pkcs7 );
        break;

    }

    out.writeObject ( this.parameters );

  }

 private void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException
  {
    // todo: revisar esto

    this.certObject = in.readInt();

    switch ( this.certObject )
    {
      case CERT:     
        this.cert = (X509Certificate) in.readObject();
        break;

      case CHAIN:     
        this.chain = (X509Certificate[]) in.readObject();
        break;

      case PKCS7:     
        this.pkcs7 = (byte[]) in.readObject();
        break;

    }
    this.parameters = (Hashtable) in.readObject();

  }
 
}
