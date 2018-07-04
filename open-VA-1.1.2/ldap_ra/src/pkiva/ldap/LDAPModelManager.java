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
import pkiva.exceptions.*;
import pkiva.management.startup.LDAPLoginConfiguration;
import pkiva.services.*;

// package protected, solo deberia interactuar con LDAPManager
class LDAPModelManager
{ //Singleton
  
  static private LDAPModelManager instance = new LDAPModelManager();
  
  static public LDAPModelManager getInstance()
  {	
    return instance;
    
  }
  
  protected LDAPModelManager()
  {
    models = new Vector( );
  }
  
  static private final int TTL = 24 * 60 * 60; // seconds
  
  private List models; // list ordenada de LDAPModels tomados en distintos modelos (primero el + reciente)
  
  /** Devuelve el modelo mas recientemente cargado, null si no hay modelos */
  public Hashtable getModel( )
  {
    Hashtable mrElements = null;
    
    // devolver el modelo mas reciente
    if ( models.size() > 0 )
    {
      LDAPModel mrModel = (LDAPModel) models.get(0);
      mrElements = mrModel.getElements();
    }
      
    return mrElements;
  }
  
  /** Devuelve la fecha con la ultima actualizacion, null si no hay modelos */
  public Date getLastUpdated ( )
  {
    Date last = null;
    
    // recoger el modelo mas reciente
    if ( models.size() > 0 )
    {
      LDAPModel mrModel = (LDAPModel) models.get(0);
      last = mrModel.getCreationDate();
    }
      
    return last;
  }
  
  /** Carga y almacena un modelo */
  public void loadModel( InitialLdapContext context ) throws LDAPAccessException
  {
    // sincronizar la lista ( si llegan mas peticiones, es mejor que esperen y que reciban contenidos actualizados)
    pkiva.log.LogManager.getLogger(this.getClass()).debug( "loadModel: Let's synchronize list" );
    synchronized ( models )
    {
      try
      {
        Hashtable hashModel = new Hashtable();
        
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "loadModel: Getting top elements" );
        Collection tops = getTopElements( context );
        Iterator topIter = tops.iterator();
        
        while ( topIter.hasNext() )
        {
          // para cada elemento superior
          EstructuralElement el = (EstructuralElement) topIter.next();
          
          // anyadimos los DPs al elemento
          el.addDPs( getDPs( context, getProperty( LDAPLoginConfiguration.BIND_DN ), el ) );
          
          // anyadimos todos sus hijos recursivamente
          el.addChildren( getElements( context, getProperty( LDAPLoginConfiguration.BIND_DN ), el ) );
          
          // y lo anyadimos al modelo
          hashModel.put( el.getName(), el );
        }
        
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "loadModel: Suplying to LDAPModelManager" );
        addModel( hashModel );
      }
      catch ( NamingException ne )
      {
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "Error loading data from server", ne );
        throw new LDAPAccessException( "Error loading data from server", ne );
      }
    } //end synchronized
    pkiva.log.LogManager.getLogger(this.getClass()).debug( "loadModel: end synchronize list" );
  }
  
  private void addModel( Hashtable t )
  {
    pkiva.log.LogManager.getLogger(this.getClass()).info("Adding new LDAPModel");
    
    // crear un nuevo LDAPModel
    LDAPModel newModel = new LDAPModel( t );
    
    // si anyadimos al principio ya no hace falta ordenar
    models.add( 0, newModel );
    //models.add( newModel );
    pkiva.log.LogManager.getLogger(this.getClass()).info("List after adding::" + models);
    
    // si anyadimos al principio ya no hace falta ordenar
    /*pkiva.log.LogManager.getLogger(this.getClass()).info("Resorting List");
    Collections.sort( models );
    pkiva.log.LogManager.getLogger(this.getClass()).info("List after sorting:" + models);*/
    
    // purgar los antiguos segun TTL (dejar siempre al menos 1, el recien insertado)
    purgeList();
    pkiva.log.LogManager.getLogger(this.getClass()).info("List after purging:" + models);
  }
  
  // purga los antiguos segun TTL (deja siempre al menos 1, el recien insertado)
  private void purgeList( )
  {
    int elementChecking = models.size() - 1; // >= 0
    boolean allOK = false; // si todos dentro de TTL
    
    while ( ( elementChecking > 0 ) && ( ! allOK ) )
    {
      // iteramos desde el final de la lista
      LDAPModel modelChecking = (LDAPModel) models.get( elementChecking );
      
      pkiva.log.LogManager.getLogger(this.getClass()).info("Checking element:" + elementChecking);
      // si se ha acabado su tiempo de vida
      if ( mustDie( modelChecking ) )
      {
        pkiva.log.LogManager.getLogger(this.getClass()).info("Element must be removed");
        // lo borramos
        models.remove( elementChecking );
        
        // actualizamos el tamanyo de la lista
        elementChecking = models.size() - 1; // >= 0
      }
      else
      {
        // como la lista esta ordenada primero el + reciente, hemos llegado a uno que esta actualizado
        // luego todos lo estan
        pkiva.log.LogManager.getLogger(this.getClass()).info("Element is OK");
        allOK = true;
      }
    } // end while
  }
  
  // indica si ha finalizado el tiempo de vida de un LDAPModel
  private boolean mustDie( LDAPModel model )
  {
    // find out expiration Date
    Calendar cal = Calendar.getInstance();
    cal.setTime( model.getCreationDate() );
    cal.add(Calendar.SECOND, TTL);
    Date expirationDate = cal.getTime();
    
    Date now = new Date();
    
    return now.after( expirationDate );
  }
  
  // TODO: UNIR ESTOS 3 METODOS EN UNO COMUN + 3 LLAMADAS DISTINTAS !!!!!!!!!!!!!!!!!!!!!!!!!
  
  private Collection getTopElements( InitialLdapContext context ) throws NamingException
  {
    Vector tops = new Vector();
    NamingEnumeration topElements = context.search( getProperty( LDAPLoginConfiguration.BIND_DN ), "o=*", null);
    
    while ( topElements.hasMore() )
    {
      SearchResult result = (SearchResult) topElements.next();
      EstructuralElement el = EstructuralElement.getEstructuralElement( result );
      pkiva.log.LogManager.getLogger(this.getClass()).info("Got TopLevel Element: " + el);
      tops.add( el );
    }
    
    return tops;
  }
  
  private Hashtable getElements( InitialLdapContext context, String search, EstructuralElement el ) throws NamingException
  {
    Hashtable children = new Hashtable();
    
    StringBuffer baseSB = new StringBuffer( el.getDistinguishedName() ).append(",").append( search);
    String base = baseSB.toString();
    
    // we search just in organization or organizationalUnit elements
    NamingEnumeration childrenEnum = context.search( base, "(| (objectClass=organization) (objectClass=organizationalUnit))", null);
    
    while ( childrenEnum.hasMore() )
    {
      SearchResult result = (SearchResult) childrenEnum.next();
      EstructuralElement child = EstructuralElement.getEstructuralElement( result );
      pkiva.log.LogManager.getLogger(this.getClass()).info("Got Non-TopLevel Element: " + child);
      String name = child.getName();
      if ( name != null )
      {
        // anyadimos los DPs al elemento
        child.addDPs( getDPs( context, base, child ) );
        
        // anyadimos sus hijos recursivamente
        child.addChildren( getElements( context, base, child ) );
        
        // Anyadimos este hijo para devolverlo
        children.put( name, child );
      }
    }
    
    return children;
  }
  
  private Vector getDPs( InitialLdapContext context, String search, EstructuralElement el ) throws NamingException
  {
    Vector dps = new Vector();
    
    StringBuffer baseSB = new StringBuffer( el.getDistinguishedName() ).append(",").append( search);
    String base = baseSB.toString();
    
    // we search just in cn elements -> Error !!, there are CN elements that are not DPs
    // NamingEnumeration childrenEnum = context.search( base, "(cn=*)", null);pkixCRLDistributionPoint

    // we search just in pkixCRLDistributionPoint or pkixOCSPDistributionPoint elements -> OK
    // NamingEnumeration childrenEnum = context.search( base, "(| (objectClass=pkixCRLDistributionPoint) (objectClass=pkixOCSPDistributionPoint))", null);

    // we search just in pkixDistributionPoint elements -> BEST, pkixDistributionPoint is parent of pkixCRLDistributionPoint, pkixOCSPDistributionPoint
    NamingEnumeration childrenEnum = context.search( base, "(objectClass=pkixDistributionPoint)", null);
    
    while ( childrenEnum.hasMore() )
    {
      SearchResult result = (SearchResult) childrenEnum.next();
      
      PKIXDistributionPoint dp = PKIXDistributionPoint.getPKIXDistributionPoint( result );
      
      if ( dp != null )
        pkiva.log.LogManager.getLogger(this.getClass()).info("Got DP:" + dp);
        dps.add( dp ); // almacenamos desordenados ... (se ordenaran despues al anyadirlos a EstructuralElement)
    }
    
    return dps;
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
