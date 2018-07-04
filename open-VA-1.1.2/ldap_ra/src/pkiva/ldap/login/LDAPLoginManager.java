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
package pkiva.ldap.login;

import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

import pkiva.services.ServiceLocator;
import pkiva.management.startup.LDAPLoginConfiguration;

public class LDAPLoginManager
{ //Singleton
  
  static private LDAPLoginManager instance = new LDAPLoginManager();
  
  static public LDAPLoginManager getInstance()
  {
    return instance;
  }
  
  protected LDAPLoginManager()
  {
  }
  
  public InitialLdapContext getContext( )
  {
    Hashtable params = loadParams();
    
    // TODO: read login module class name
    String className = "pkiva.ldap.login.UserPassLoginModule";
    // ... reflection
    
    // invoke module
    pkiva.log.LogManager.getLogger(this.getClass()).debug("LDAP Login via UserPassLoginModule. Params:" + params);
    GenericLoginModule loginModule = new UserPassLoginModule( params );
    InitialLdapContext context = loginModule.getContext( );
    return context;
  }

  public String getURL ( )
  {
    return getProperty( LDAPLoginConfiguration.PROVIDER_URL );
  }
  
  protected Hashtable loadParams()
  {
    Hashtable params = new Hashtable();
    
    params.put( Context.INITIAL_CONTEXT_FACTORY, getProperty( LDAPLoginConfiguration.INITIAL_CONTEXT_FACTORY ) );
    params.put( Context.PROVIDER_URL, getProperty( LDAPLoginConfiguration.PROVIDER_URL ) );
    params.put( Context.SECURITY_PRINCIPAL, getProperty( LDAPLoginConfiguration.SECURITY_PRINCIPAL ) );
    params.put( Context.SECURITY_CREDENTIALS, getProperty( LDAPLoginConfiguration.SECURITY_CREDENTIALS ) );
    
    /*params.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
    params.put( Context.PROVIDER_URL, "ldap://172.18.16.229:389" );
    params.put( Context.SECURITY_PRINCIPAL, "cn=Manager,dc=DirecTrust,dc=com" );
    params.put( Context.SECURITY_CREDENTIALS, "admin" );*/
    
    return params;
  }
  
  protected String getProperty( String name )
  {
    try
    {
      return ServiceLocator.getInstance().getProperty( name );
    }
    catch (Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error getting Property:" + name, e);
      return null;
    }
  }
}
