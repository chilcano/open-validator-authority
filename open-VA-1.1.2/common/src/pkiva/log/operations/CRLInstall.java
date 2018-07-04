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
import java.security.cert.X509CRL;
import java.security.cert.CRLException;

public class CRLInstall extends AuditOperation
{

  public CRLInstall ( )
  {
    super ( AuditOperation.CRL_INSTALL );
  }

  // Request Keys
  public void setURL ( String s )
  {
    addToRequest ( AuditKeys.URL , AuditValue.newAsVarchar( s ) );
  }

  // Response Keys
  public void setCRL ( X509CRL crl ) throws CRLException
  {
    addToResponse ( AuditKeys.CRL , AuditValue.newAsBlob( crl.getEncoded() ) );
  }

}
