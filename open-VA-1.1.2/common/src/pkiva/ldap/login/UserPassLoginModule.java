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

public class UserPassLoginModule extends GenericLoginModule
{
  
  // TODO: cogerlo por configuracion ??
  /* numero de intentos de conexion*/
  private int retry = 3;
  
  
  public UserPassLoginModule( Object params ) throws IllegalArgumentException
  {
    if ( params instanceof Hashtable )
    {
      this.env = (Hashtable) params;
    }
    else
    {
      throw new IllegalArgumentException( );
    }
  }
  
  /**
   * Devuelve un contexto LDAP
   */
  public InitialLdapContext getContext( )
  {
    return createConnection();
  }
  
  /**
   * Crea una conexion
   */
  protected InitialLdapContext createConnection()
  {
    InitialLdapContext context = null;
    for(int k = 0; ( k <= this.retry  && context == null ); k++)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Creando la conexion");
      try
      {
        context = this.connect();
        
        if ( context == null )
          throw new NamingException();
        
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Conexion creada." + context);
        
      }
      catch(javax.naming.NamingException nE)
      {
        if ( context != null )
          try
          {
            context.close();
          }
          catch( Throwable t )
          {}
        
        if ( k == ( this.retry - 1 ) )
        {
          pkiva.log.LogManager.getLogger(this.getClass()).error(" Conexion abortada numero de reintentos agotados.", nE);
          return null;
        }
        else
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Realizando reintento de conexion " + ( k + 1 ));
        
        context = null;
      }
    }
    return context;
    
  }
  
  protected InitialLdapContext connect() throws NamingException
  {
    InitialLdapContext contextOut = null;
    
    contextOut = new InitialLdapContext( env, null );
    
    
    return contextOut;
  }
  
}
