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
package pkiva.validation.ocsp.connectors;

import java.security.cert.*;
import pkiva.validation.ocsp.*;

public class OCSPValidationResponse 
{

  public static final short OK = 0;
  public static final short REVOKED = 1;
  public static final short ERROR = 2;
  public static final short UNKNOWN = 3;

  protected static final String[] states = { "OK", "REVOKED", "ERROR", "UNKNOWN" };

  protected short state;
  protected Throwable cause;
  protected OCSPValidationInfo info;

  public OCSPValidationResponse( short st )
  {
    this.state = st;
    cause = null;
    info = null;
  }

  public short getState()
  {
    return this.state;
  }

/*
  public void setState(  )
  {
  }
*/

  public Throwable getCause()
  {
    return this.cause;
  }

  public void setCause ( Throwable t )
  {
    this.cause = t;
  }

  public OCSPValidationInfo getInfo()
  {
    return this.info;
  }

  public void setInfo( OCSPValidationInfo newInfo )
  {
    this.info = newInfo;
  }

  public String toString ( )
  {
    StringBuffer sb = new StringBuffer ( states[state] );

    if (cause != null)
    {
      sb.append ( " - " ).append ( cause.toString() );
    }
    
    return sb.toString();
  }
  
}
