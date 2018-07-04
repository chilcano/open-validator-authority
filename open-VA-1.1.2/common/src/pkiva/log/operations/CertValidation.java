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
package pkiva.log.operations;

import pkiva.log.AuditOperation;
import pkiva.log.AuditKeys;
import pkiva.log.AuditValue;
import pkiva.services.*;
import pkiva.exceptions.*;
import java.security.cert.X509Certificate;
import java.security.cert.TrustAnchor;

public class CertValidation extends AuditOperation
{

  public CertValidation ( )
  {
    super ( AuditOperation.CERTIFICATE_VALIDATION );
  }

  // Request Keys
  public void setCert ( X509Certificate cert ) throws AuditingException 
  {
    if ( cert != null )
    {
      try
      {
        setIssuer ( cert.getIssuerDN().getName() );
        setSubject ( cert.getSubjectDN().getName() );
        setSerialNumber ( CertUtils.getSerialNumberAsHexa (  cert ) );
        setFingerPrint ( CertUtils.getFingerPrintAsHexa ( cert ) );
      }
      catch ( Exception e)
      {
        throw new AuditingException ( "Exception auditing certificate data", e);
      }
    }
  }

  public void setIssuer ( String s )
  {
    addToRequest ( AuditKeys.CERT_ISSUER , AuditValue.newAsVarchar( s ) );
  }

  public void setSubject ( String s )
  {
    addToRequest ( AuditKeys.CERT_SUBJECT , AuditValue.newAsVarchar( s ) );
  }

  public void setSerialNumber ( String s )
  {
    addToRequest ( AuditKeys.CERT_SERIAL_NUMBER , AuditValue.newAsVarchar( s ) );
  }

  public void setFingerPrint ( String s )
  {
    addToRequest ( AuditKeys.CERT_FINGERPRINT , AuditValue.newAsVarchar( s ) );
  }

  public void setPolicies ( String s )
  {
    addToRequest ( AuditKeys.POLICIES , AuditValue.newAsVarchar( s ) );
  }

  public void setVCRequest ( String s )
  {
    addToRequest ( AuditKeys.VALIDATION_CHANNEL , AuditValue.newAsVarchar( s ) );
  }

  // Response Keys
  public void setState ( String s )
  {
    addToResponse ( AuditKeys.VALIDATION_STATE , AuditValue.newAsVarchar( s ) );
  }

  public void setVCResponse ( String s )
  {
    addToResponse ( AuditKeys.VALIDATION_CHANNEL , AuditValue.newAsVarchar( s ) );
  }

  public void setRevocationObject ( byte[] b )
  {
    addToResponse ( AuditKeys.REVOCATION_OBJECT , AuditValue.newAsBlob( b ) );
  }

  public void setPolicyTree ( String s )
  {
    addToResponse ( AuditKeys.POLICY_TREE , AuditValue.newAsVarchar( s ) );
  }

  public void setTrustAnchor ( TrustAnchor ta ) throws AuditingException
  {
    try
    {
      X509Certificate taCert = ta.getTrustedCert();
      if ( taCert != null)
      {
        setTrustAnchorSubject ( taCert.getSubjectDN().getName() );
        setTrustAnchorSN ( CertUtils.getSerialNumberAsHexa (  taCert ) );
        setTrustAnchorFingerPrint ( CertUtils.getFingerPrintAsHexa ( taCert ) );
      }
      else
        setTrustAnchorSubject ( ta.getCAName() );
    }
    catch ( Exception e)
    {
      throw new AuditingException ( "Exception auditing certificate data", e);
    }

  }

  public void setTrustAnchorSubject ( String s )
  {
    addToResponse ( AuditKeys.TRUST_ANCHOR_SUBJECT , AuditValue.newAsVarchar( s ) );
  }

  public void setTrustAnchorSN ( String s )
  {
    addToResponse ( AuditKeys.TRUST_ANCHOR_SERIAL_NUMBER , AuditValue.newAsVarchar( s ) );
  }

  public void setTrustAnchorFingerPrint ( String s )
  {
    addToResponse ( AuditKeys.TRUST_ANCHOR_FINGERPRINT , AuditValue.newAsVarchar( s ) );
  }



}
