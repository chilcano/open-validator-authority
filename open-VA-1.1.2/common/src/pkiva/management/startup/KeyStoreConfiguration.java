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


public class KeyStoreConfiguration extends GenericPropertiesStartup
{
  public static final String KEYSTORE_NAME = "pkiva.trustStore.keyStore.name";
  public static final String KEYSTORE_TYPE = "pkiva.trustStore.keyStore.type";
  public static final String KEYSTORE_PROVIDER = "pkiva.trustStore.keyStore.provider";
  
  public KeyStoreConfiguration ()
  {
    PROPERTIES_FILE = "KeyStoreConfiguration.properties";
    INFO = "KeyStore configuration";
  }
 
  public static void main(String[] args)
  {
    KeyStoreConfiguration startup = new KeyStoreConfiguration ();
    startup.load();
  }
}


