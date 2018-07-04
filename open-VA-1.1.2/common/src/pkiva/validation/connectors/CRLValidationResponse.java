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
package pkiva.validation.connectors;

import java.util.*;
import pkiva.exceptions.*;

public class CRLValidationResponse 
{

  protected Collection crlCollection;
  
  protected CRLValidationException error;

  public CRLValidationResponse( Collection col )
  {
    this.crlCollection = col;
  }
  
  public CRLValidationResponse( Throwable t )
  {
    this.error = new CRLValidationException ( "Internal error retrieving CRL's:" + t.getMessage(), t );
  }
  
  /** Getter for property crlCollection.
   * @return Value of property crlCollection.
   *
   */
  public java.util.Collection getCrlCollection()
  {
    return crlCollection;
  }  

  /** Getter for property error.
   * @return Value of property error.
   *
   */
  public CRLValidationException getError()
  {
    return error;
  }
  
  public String toString ( )
  {
    if ( crlCollection != null )
      return crlCollection.toString();
    else
      return error.toString();
  }
  
}
