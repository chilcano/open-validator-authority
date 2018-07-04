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

public class SignatureValidation extends AuditOperation
{

  public SignatureValidation ( )
  {
    super ( AuditOperation.SIGNATURE_VALIDATION );
  }

  // Request Keys
  public void setPKCS7 ( byte[] pkcs7 )
  {
    addToRequest ( AuditKeys.PKCS7 , AuditValue.newAsBlob( pkcs7 ) );
  }

  public void setContent ( byte[] content )
  {
    addToRequest ( AuditKeys.CONTENT , AuditValue.newAsBlob( content ) );
  }

  public void setDigest ( byte[] digest )
  {
    addToRequest ( AuditKeys.DIGEST , AuditValue.newAsBlob( digest ) );
  }

  // Response Keys
  public void setResult ( boolean b )
  {
    addToResponse ( AuditKeys.SUCCESS , AuditValue.newAsVarchar( Boolean.toString( b ) ) );
  }

}
