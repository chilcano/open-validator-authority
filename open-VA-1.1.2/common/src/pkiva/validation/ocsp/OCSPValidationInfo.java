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
package pkiva.validation.ocsp;

import java.util.*;
import java.security.cert.*;
import pkiva.validation.ValidationObject;

/**
 *
 * @author  diriarte
 */
public class OCSPValidationInfo extends ValidationObject
{
  protected Collection ok;
  protected Collection revoked;
  protected Collection unknown;
  protected X509Certificate ocspCert;
  protected byte[] ocspData;
  
  /** Creates a new instance of OCSPValidationInfo */
  public OCSPValidationInfo(Collection ok, Collection revoked, Collection unknown)
  {
    this.ok = ok;
    this.revoked = revoked;
    this.unknown = unknown;
    this.ocspCert = null;
    this.ocspData = null;
  }

  public String toString( )
  {
    StringBuffer sb = new StringBuffer ( "OCSPValidation:" );

    if ( ( ok != null ) && ( ok.size() > 0 ) )
      sb.append ( "\n\tOK:" ).append (ok);
    if ( ( revoked != null ) && ( revoked.size() > 0 ) )
      sb.append ( "\n\tRevoked:" ).append (revoked);
    if ( ( unknown != null ) && ( unknown.size() > 0 ) )
      sb.append ( "\n\tUnknown:" ).append (unknown);
    if ( ocspCert != null )
      sb.append ( "\n\tOCSPCert:" ).append (ocspCert);
    if ( ocspData != null )
      sb.append ( "\n\tOCSPData Length:" ).append (ocspData.length);

    return sb.toString();
  }
  
  /** Getter for property ok.
   * @return Value of property ok.
   *
   */
  public java.util.Collection getOk()
  {
    return ok;
  }
  
  /** Getter for property revoked.
   * @return Value of property revoked.
   *
   */
  public java.util.Collection getRevoked()
  {
    return revoked;
  }
  
  /** Getter for property unknown.
   * @return Value of property unknown.
   *
   */
  public java.util.Collection getUnknown()
  {
    return unknown;
  }

  public X509Certificate getOCSPCert()
  {
    return this.ocspCert;
  }

  public void setOCSPCert ( X509Certificate t )
  {
    this.ocspCert = t;
  }

  public byte[] getOCSPData()
  {
    return this.ocspData;
  }

  public void setOCSPData ( byte[] t )
  {
    this.ocspData = t;
  }

  
}
