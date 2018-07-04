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
package pkiva.validation.io;

import java.util.Properties;
import java.security.cert.X509CRL;
import pkiva.exceptions.*;

public abstract class GenericFetcher
{
  
  protected String location;
  
  protected Properties params;
  
  protected GenericFetcher( String loc, Properties props )
  {
    this.location = loc;
    this.params = props;
    if ( params == null )
    {
      params = new Properties ();
    }
  }
  
  public abstract X509CRL getCRL() throws FetchingException;
}
