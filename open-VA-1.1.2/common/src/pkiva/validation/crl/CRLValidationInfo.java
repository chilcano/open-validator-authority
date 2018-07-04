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
package pkiva.validation.crl;

import java.io.*;
import java.security.cert.*;
import java.util.*;
import pkiva.validation.ValidationObject;

/**
 *
 * @author  diriarte
 */
public class CRLValidationInfo extends ValidationObject
{
  protected Collection crlsCol;
  protected boolean rev;

  /** Creates a new instance of CRLValidationInfo */
  public CRLValidationInfo( boolean revoked, Collection crls)
  {
    this.crlsCol = crls;
    this.rev = revoked;
  }

  public Collection getCrls ( )
  {
    return this.crlsCol ;
  }

  public boolean getRevoked ( )
  {
    return this.rev ;
  }

  public String toString ( )
  {
    return crlsCol.toString();
  }

  private void writeObject(java.io.ObjectOutputStream out)
     throws IOException, ClassNotFoundException
  {
    out.writeBoolean ( rev );

    if ( ( crlsCol != null ) && ( ! crlsCol.isEmpty() ) )
    {
      Iterator iter = crlsCol.iterator();
      while ( iter.hasNext() )
      {
        X509CRL item = (X509CRL) iter.next();
        try
        {
          out.writeObject ( item.getEncoded() );
        }
        catch ( Throwable ignored )
        {
        }
      } // end while
    } // end if
  }

  private void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException
  {
    this.rev = in.readBoolean();

    this.crlsCol = new Vector();
    Object obj = in.readObject();

    while ( obj != null )
    {
      if ( obj instanceof byte[] )
      {
        try
        {
          X509CRL crl = getCRLfromByteArray( (byte[]) obj );
          crlsCol.add ( crl );
        }
        catch ( Throwable ignored )
        {
        }
      } // end if

      try
      {
        obj = in.readObject();
      }
      catch ( OptionalDataException eofArrived )
      {
        obj = null;
      }
    } // end while
  }

  private static X509CRL getCRLfromByteArray( byte[] buf ) throws CRLException, CertificateException
  {
    ByteArrayInputStream bais = new ByteArrayInputStream( buf );
    return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL( bais );
  }

}
