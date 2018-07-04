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
//import java.security.cert.*;
//import java.io.*;
//import pkiva.exceptions.*;

public class TESTFetcher extends GenericFetcher
{
  
  public TESTFetcher(String loc, Properties props)
  {
    super( loc, props );
  }
  
  public java.security.cert.X509CRL getCRL() 
  {
    pkiva.log.LogManager.getLogger(this.getClass()).info("Request to (NOT) fetch (TEST):" + this.location);
    return null;
  }
  
}
