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
import java.io.*;
import java.util.Set;
import pkiva.validation.ValidationObject;

/** This class holds information obtained from Certificate Validation Process
 * @author diriarte
 */
public class CertValidationResponse implements java.io.Serializable
{
    //0, unknown
    /** UNKNOWN state */
    public static final short UNKNOWN = 0;
    
    //2xx series, ok
    /** OK state */    
    public static final short GOOD = 200;
    
    //3xx series, certificate error
    /** REVOKED state */
    public static final short REVOKED = 300;
    /** INVALID_POLICY state */
    public static final short INVALID_POLICY = 301;
    /** REVOKED by hold state */
    public static final short SUSPENDED = 302;
    /** Expired */
    public static final short EXPIRED = 303;
    /** Not yet valid */
    public static final short NOT_YET_VALID = 304;

    //4xx series, certchain error
    /** INVALID_CERTCHAIN state */
    public static final short INVALID_CERTCHAIN = 400;
    /** CERTCHAIN_NOT_FOUND state */
    public static final short CERTCHAIN_NOT_FOUND = 404;
    
    //5xx series, internal server error
    //public static final short INTERNAL_SERVER_ERROR = 500;

  /************************     VALIDATION CHANNELS ************************/
//    public static final short UNKNOWN = 0;
//    public static final short CRL = 1;
//    public static final short OCSP = 2;
//    public static final short ONLY_TRUSTANCHOR = 3;

  /************************************************************************/

    protected short state;
    protected X509Certificate[] chain; // ?
    protected String validationChannel;
    protected Set policies; // ?
    protected ValidationObject validationInfo;

    protected PKIXCertPathValidatorResult result; 
    protected Throwable errorCause;
    
  /************************************************************************/

    /** Creates a new instance of CertValidationResponse
     * @param validState state from validation
     */
  public CertValidationResponse(short validState)
  {
    this.state = validState;
  }

  /**
   * @return String representation from state
   */  
  public String getStateDescription()
  {
      switch(state){
          case UNKNOWN: return "UNKNOWN";
          case GOOD: return "GOOD";
          case REVOKED: return "REVOKED";
          case SUSPENDED: return "SUSPENDED";
          case INVALID_POLICY: return "INVALID_POLICY";
          case INVALID_CERTCHAIN: return "INVALID_CERTCHAIN";
          case CERTCHAIN_NOT_FOUND: return "CERTCHAIN_NOT_FOUND";
          case EXPIRED: return "EXPIRED";
          case NOT_YET_VALID: return "NOT_YET_VALID";
      }
      return ""+state;
  }
  
  /**
   * @return true if state is GOOD
   */  
  public boolean isValid ( )
  {
    return getState() == GOOD;
  }
  
  public String toString()
  {
    StringBuffer sb = new StringBuffer("\n");
    
    sb.append ( getStateDescription() );
    
    if ( validationChannel != null )
      sb.append ( "\n\tChannel: " ).append ( this.getValidationChannel() );
    if ( validationInfo != null )
      sb.append ( "\n\tInfo: " ).append ( validationInfo );
    if ( policies != null )
      sb.append ( "\n\tPolicies: " ).append ( policies );
    if ( chain != null )
      sb.append ( "\n\tCertificates in chain: " ).append ( chain.length );
    if ( result != null )
      sb.append ( "\n\tResult: " ).append ( result );
    if ( errorCause != null )
      sb.append ( "\n\tError Cause: " ).append ( errorCause.toString() );
    
    return sb.toString();
  }
  
  /**
   * @return String formatted to audit purposes
   */  
  public String toAuditString()
  {
    StringBuffer sb = new StringBuffer();
    
    sb.append ( getStateDescription() );
    
    if ( ( chain != null ) && ( chain.length > 0 ) )
    {
      sb.append ( "\n\tIssuer Name: " ).append ( this.chain[0].getIssuerDN().getName() );
      sb.append ( "\n\tSerial Number: " ).append ( this.chain[0].getSerialNumber() );
    }
    if ( validationChannel != null )
      sb.append ( "\n\tChannel: " ).append ( this.getValidationChannel() );
    if ( policies != null )
      sb.append ( "\n\tPolicies: " ).append ( policies );
    if ( errorCause != null )
      sb.append ( "\n\tError Cause: " ).append ( errorCause.toString() );
    
    return sb.toString();
  }
  
  /************************************************************************/
  
//  protected String getValidationChannnel ()
//  {
//    switch ( validationChannel )
//    {
//      case CRL: return "CRL";
//      case OCSP: return "OCSP";
//      case ONLY_TRUSTANCHOR: return "ONLY_TRUSTANCHOR";
//      default: return "UNKNOWN";
//    }
//  }
  /********************* R/W METHODS *********************/

  /** Getter for property state.
   * @return Value of property state.
   *
   */
  public short getState()
  {
    return state;
  }
  
  /** Getter for property chain.
   * @return Value of property chain.
   *
   */
  public java.security.cert.X509Certificate[] getChain()
  {
    return this.chain;
  }
  
  /** Setter for property chain.
   * @param chain New value of property chain.
   *
   */
  public void setChain(java.security.cert.X509Certificate[] chain)
  {
    this.chain = chain;
  }
  
  /** Getter for property validationChannel.
   * @return Value of property validationChannel.
   *
   */
  public String getValidationChannel()
  {
    return validationChannel;
  }
  
  /** Setter for property validationChannel.
   * @param validationChannel New value of property validationChannel.
   *
   */
  public void setValidationChannel(String validationChannel)
  {
    this.validationChannel = validationChannel;
  }
  
  /** Getter for property policies.
   * @return Value of property policies.
   *
   */
  public java.util.Set getPolicies()
  {
    return policies;
  }
  
  /** Setter for property policies.
   * @param policies New value of property policies.
   *
   */
  public void setPolicies(java.util.Set policies)
  {
    this.policies = policies;
  }
  
  /** Getter for property validationInfo.
   * @return Value of property validationInfo.
   *
   */
  public pkiva.validation.ValidationObject getValidationInfo()
  {
    return validationInfo;
  }
  
  /** Setter for property validationInfo.
   * @param validationInfo New value of property validationInfo.
   *
   */
  public void setValidationInfo(pkiva.validation.ValidationObject validationInfo)
  {
    this.validationInfo = validationInfo;
  }
  
  /** Getter for property result.
   * @return Value of property result.
   *
   */
  public PKIXCertPathValidatorResult getResult()
  {
    return result;
  }
  
  /** Setter for property result.
   * @param theResult New value of property result.
   */
  public void setResult(PKIXCertPathValidatorResult theResult)
  {
    this.result = theResult;
  }
  
  /** Getter for property errorCause.
   * @return Value of property errorCause.
   *
   */
  public java.lang.Throwable getErrorCause()
  {
    return errorCause;
  }
  
  /** Setter for property errorCause.
   * @param errorCause New value of property errorCause.
   *
   */
  public void setErrorCause(java.lang.Throwable errorCause)
  {
    this.errorCause = errorCause;
  }

 private void writeObject(java.io.ObjectOutputStream out)
     throws IOException, ClassNotFoundException
  {
    // todo: revisar esto
    out.writeShort ( state );
    out.writeObject ( chain ); 
    out.writeObject ( validationChannel );
    out.writeObject ( policies ); 
    out.writeObject ( validationInfo ); // error java.io.NotSerializableException: sun.security.x509.X509CRLImpl
    out.writeObject ( errorCause ); 

    //out.writeObject ( result );
    writePKIXCertPathValidatorResult ( result, out );
  }

 private void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException
  {
    // todo: revisar esto
    this.state = in.readShort();
    this.chain = (X509Certificate[]) in.readObject(); 
    this.validationChannel = (String) in.readObject();
    this.policies = (Set) in.readObject(); 
    this.validationInfo = (ValidationObject) in.readObject();
    this.errorCause = (Throwable) in.readObject();

    //this.result = (PKIXCertPathValidatorResult) in.readObject(); 
    this.result =  readPKIXCertPathValidatorResult ( in );
  }

  private static void writePKIXCertPathValidatorResult ( PKIXCertPathValidatorResult object, java.io.ObjectOutputStream out ) 
    throws IOException, ClassNotFoundException
  {
    if ( object == null )
      return;

    PolicyNode tree = object.getPolicyTree(); // java.security.cert.PolicyNode is not serializable and don't know how to do it

    PublicKey key = object.getPublicKey(); // java.security.PublicKey is serializable
    out.writeObject ( key );

    TrustAnchor ta = object.getTrustAnchor(); // java.security.cert.TrustAnchor is not serializable, but we can find a work-around
    X509Certificate taCert = ta.getTrustedCert();
    if ( taCert != null )
    {
      out.writeObject ( taCert ); 
    }
    else
    {
      PublicKey pk = ta.getCAPublicKey();
      out.writeObject ( pk ); 
      String name = ta.getCAName();
      out.writeObject ( name ); 
    }
    byte[] cons = ta.getNameConstraints();
    out.writeObject ( cons ); 
  }
  
  private static PKIXCertPathValidatorResult readPKIXCertPathValidatorResult ( java.io.ObjectInputStream in ) 
    throws IOException, ClassNotFoundException
  {
    try
    {
      PolicyNode tree = null; // java.security.cert.PolicyNode is not serializable and don't know how to do it

      PublicKey key = (PublicKey) in.readObject(); // java.security.PublicKey is serializable

      TrustAnchor ta = null; // java.security.cert.TrustAnchor is not serializable, but we can find a work-around
      Object nextObj = in.readObject();
      X509Certificate taCert = null;
      java.security.PublicKey pk = null;
      String name = null;
      if ( nextObj instanceof X509Certificate )
      {
        taCert = (X509Certificate) nextObj;
      }
      else if ( nextObj instanceof PublicKey )
      {
        pk = (PublicKey) nextObj;
        name = (String) in.readObject();
      }
      else
      {
        return null;
      }

      byte[] cons = (byte[]) in.readObject();

      if ( taCert != null )
      {
        ta = new TrustAnchor ( taCert, cons );
      }
      else
      {
        ta = new TrustAnchor ( name, pk, cons );
      }

      // we've built the TrustAnchor

      return new PKIXCertPathValidatorResult ( ta, tree, key);
    }
    catch ( OptionalDataException eof )
    {
      return null;
    }
  }
  
}
