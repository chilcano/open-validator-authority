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
import java.security.cert.X509Certificate;
import pkiva.exceptions.*;
import pkiva.services.*;

public class CertDataExtraction extends AuditOperation
{

  public CertDataExtraction ( )
  {
    super ( AuditOperation.CERTIFICATE_DATA_EXTRACTION );
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

  public void setDataPath ( String s )
  {
    addToRequest ( AuditKeys.DATA_EXTRACTION_PATH , AuditValue.newAsVarchar( s ) );
  }

  // Response Keys
  public void setDataItem ( String s )
  {
    addToResponse ( AuditKeys.DATA_EXTRACTION_ITEM , AuditValue.newAsVarchar( s ) );
  }

}
