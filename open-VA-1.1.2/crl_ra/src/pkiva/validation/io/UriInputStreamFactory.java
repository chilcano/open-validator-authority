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
import java.lang.reflect.*;
import java.io.IOException;
public class UriInputStreamFactory
{
  
  public static UriInputStream getInstance(String strUri,Properties props) throws IOException
  {
    try
    {
      StringBuffer streamClassSB = new StringBuffer ( "pkiva.validation.io." )
		  .append ( getProtocolName(strUri).toUpperCase() )
		  .append ( "InputStream" );
      Class classDefinition = Class.forName( streamClassSB.toString() );
      Class[] argsclass=new Class[]
      {String.class , Properties.class};
      Object[] args=new Object[]
      {strUri,props};
      Constructor cons=classDefinition.getConstructor(argsclass);
      UriInputStream obj=(UriInputStream) cons.newInstance(args);
      obj.open();
      return obj;
    }catch(Exception e)
    {
	  pkiva.log.LogManager.getLogger("pkiva.validation.io.UriInputStreamFactory").error("Error al crear la instancia de UriInputStream. URI:" + strUri, e );
      throw new IOException("Error al crear la instancia de UriInputStream. URI:" + strUri + ":" + e.getMessage());
    }
    
  }
  
  private static String getProtocolName(String strUri)
  {
    int i=strUri.indexOf(":");
    return strUri.substring(0,i);
  }
}
