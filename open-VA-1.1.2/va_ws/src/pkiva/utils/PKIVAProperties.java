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
package pkiva.utils;

import java.io.InputStream;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;



/**
 * @author rnavalon
 */
public final class PKIVAProperties {

	private static Properties properties;
	
	private static synchronized void init() {
		
		if ( properties == null ) {
			
			properties = new Properties();
			
			Log.info("Loading properties once");
			
			try {
				InputStream propStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("pkiva.webservices.properties");
				
				if ( propStream == null ) {
					Log.warning("Configuration file not found");
				}
				else {
					properties.load( propStream  );
					propStream.close();
				}
			} catch( Exception e ) {
				Log.error( "Error reading configuration file" , e );
			}
			
			String propertyName;
			for( Iterator it = properties.keySet().iterator(); it.hasNext(); ) {
				propertyName = (String)it.next();
				
				Log.info( propertyName + " = " + getProperty(propertyName) );
			}
		}
	}
	
	private static Properties getProperties() {
		if ( properties == null ) {
			init();
		}
		
		return properties;
	}
	public static String getProperty( String propertyName ) {
		String propertyValue;
		
		propertyValue = getProperties().getProperty(propertyName);
		if ( propertyValue != null && propertyValue.length() == 0 ) {
			propertyValue = null;
		}
		
		return propertyValue;
	}
	
	public static String getProperty( String propertyName , String defaultValue ) {
		String propertyValue;
		
		propertyValue = getProperties().getProperty(propertyName, defaultValue);
		if ( propertyValue != null && propertyValue.length() == 0 ) {
			propertyValue = null;
		}
		
		return propertyValue;
	}
	
	public static String[] getArrayProperties( String propertyName ) {
		String[] properties = null;
		List aList = new ArrayList();
		
		String propertyValue;
		for( int i = 1; ; i++ ) {
			propertyValue = getProperty( propertyName + "." + i );
			if ( propertyValue == null ) break;
			
			aList.add( propertyValue );
		}
		
		if ( aList.size() != 0 ) {
			properties = new String[ aList.size() ];
			for( int i = 0; i < properties.length; i++ ) {
				properties[i] = (String)aList.get(i);
			}
		}
		
		return properties;
	}
}
