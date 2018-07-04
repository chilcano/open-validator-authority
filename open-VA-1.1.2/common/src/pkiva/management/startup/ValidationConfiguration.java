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


public class ValidationConfiguration extends GenericPropertiesStartup
{
  public static final String INITIAL_CONTEXT_FACTORY = "pkiva.ldap.login.contextFactory";
  public static final String PROVIDER_URL = "pkiva.ldap.login.providerURL";
  public static final String SECURITY_PRINCIPAL = "pkiva.ldap.login.principal";
  public static final String SECURITY_CREDENTIALS = "pkiva.ldap.login.credentials";
  
  public ValidationConfiguration ()
  {
    PROPERTIES_FILE = "ValidationConfiguration.properties";
    INFO = "Validation algorithm configuration";
  }
 
  public static void main(String[] args)
  {
    ValidationConfiguration startup = new ValidationConfiguration();
    startup.load();
  }
}


