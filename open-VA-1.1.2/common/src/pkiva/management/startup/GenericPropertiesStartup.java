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
package pkiva.management.startup;

import pkiva.services.*;
import java.util.*;
import java.io.*;

/**
 *
 * @author  diriarte
 */
public abstract class GenericPropertiesStartup
{
  protected String PROPERTIES_FILE = "Child classes must override fileName";
  protected String INFO = "Properties";
  
  protected Properties getProperties( ) throws IOException
  {
    return getProperties( PROPERTIES_FILE );
  }
  
  protected Properties getProperties( String fileName ) throws IOException
  {
    InputStream is = this.getClass().getClassLoader().getResourceAsStream(fileName);

    if ( is == null )
    {
      throw new FileNotFoundException ( "File not found: " + fileName );
    }
    
    Properties p = new Properties();
    p.load(is);
    
    return p;
    
  }
  
  public void load( )
  {
    try
    {
      pkiva.log.LogManager.getLogger(this.getClass()).info("Loading " + INFO );
      
      // open properties file
      Properties p = getProperties();
      
      // load properties in jndi tree
      ServiceLocator.getInstance().loadProperties( p );
      
      pkiva.log.LogManager.getLogger(this.getClass()).info( INFO + " loaded successfully" );
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error( "Error loading " + INFO, e );
    }
  }

}
