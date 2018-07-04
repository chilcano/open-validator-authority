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
package pkiva.ldap;

import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import pkiva.ldap.login.*;
import pkiva.log.*;
import pkiva.log.operations.*;
import pkiva.exceptions.*;

public class LDAPManager
{ //Singleton
  
  static private LDAPManager instance = new LDAPManager();
  
  static public LDAPManager getInstance()
  {
    return instance;
  }
  
  protected LDAPManager()
  {
  }
  
  public void loadData( ) throws LDAPAccessException
  {
    InitialLdapContext context = null;
    LDAPLoad auditOper = new LDAPLoad ();
    try
    {
      pkiva.log.LogManager.getLogger(this.getClass()).debug( "loadData: Let's log on" );
      context = doLogin();
      auditOper.setURL ( getURL() );
      LDAPModelManager.getInstance().loadModel( context );
      pkiva.log.LogManager.getLogger(this.getClass()).info("Load data from LDAP server performed");
      //pkiva.log.AuditManager.getAuditer(this.getClass()).audit("Load data from LDAP server performed");
      auditOper.setSuccess ( true );
      pkiva.log.AuditManager.getAuditer(this.getClass()).audit(auditOper);
    }
    catch ( LDAPAccessException lae )
    {
      auditOper.setError ( lae );

      try
      {
        pkiva.log.AuditManager.getAuditer(this.getClass()).audit(auditOper);
      }
      catch ( AuditingException ae )
      {
        throw new LDAPAccessException ( "Internal error auditing: ", ae);
      }

      throw lae;
    }
    catch ( AuditingException ae )
    {
      throw new LDAPAccessException ("Internal Error loading data. Couldn't not do audit", ae);
    }
    finally
    {
      try
      {
        if ( context != null )
        {
          context.close();
        }
      }
      catch ( Exception e){}
    }
  }
  
  public EstructuralElement getEstructuralElement( String name ) throws LDAPAccessException
  {
    return (EstructuralElement) getModel().get( name );
  }
  
  public Collection getTopLevelElements( ) throws LDAPAccessException
  {
    return getModel().values();
  }
  
  // devuelve todas las CAs que cuelgan del modelo, recursivamente
  public Collection collectCAs( ) throws LDAPAccessException
  {
    Collection result = new Vector();
    
    Collection topLevel = getTopLevelElements();
    
    Iterator iter = topLevel.iterator();
    while ( iter.hasNext() )
    {
      EstructuralElement el = (EstructuralElement) iter.next();
      
      // filtramos solo las CAs
      if ( el.isCA() )
        result.add( el );
      
      result.addAll( el.collectCAs( ) );
    }
    
    return result;
  }
  
  /** Devuelve la fecha con la ultima actualizacion del LDAP, null si no hay modelos */
  public Date getLastUpdated( )
  {
    return LDAPModelManager.getInstance().getLastUpdated( );
  }
  
  private Hashtable getModel( ) throws LDAPAccessException
  {
    Hashtable t = LDAPModelManager.getInstance().getModel( );
    
    if ( t == null ) // y si aun no ha sido cargado ??
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn( "Don't have data. Let's try to perform an initial load" );
      loadData();
      t = LDAPModelManager.getInstance().getModel( );
      
      if ( t == null ) // y si aun no ha sido cargado ?? -> Houston, we've got ...
      {
        pkiva.log.LogManager.getLogger(this.getClass()).error( "Don't have data even after loading. Seems to be a problem loading Data" );
        throw new LDAPAccessException( "Can't get model after trying to load" );
      }
    }
    
    return t;
  }
  
  
  private InitialLdapContext doLogin( )
  {
    return LDAPLoginManager.getInstance().getContext();
  }
  
  private String getURL( )
  {
    return LDAPLoginManager.getInstance().getURL();
  }
}
