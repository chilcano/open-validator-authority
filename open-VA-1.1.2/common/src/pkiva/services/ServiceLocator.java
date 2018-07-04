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
package pkiva.services;
import java.util.*;
import javax.naming.*;
import java.rmi.RemoteException;
import javax.ejb.*;
import javax.rmi.PortableRemoteObject;
import javax.resource.cci.*;
import java.io.*;
import pkiva.exceptions.ServiceLocatorException;
import pkiva.management.startup.LDAPLoginConfiguration;
import pkiva.management.startup.KeyStoreConfiguration;
import pkiva.management.startup.ValidationConfiguration;
import pkiva.ldap.connectors.LDAPJBDirContextFactory;
import pkiva.validation.connectors.CRLJBDirContextFactory;
import pkiva.validation.ocsp.connectors.OCSPJBDirContextFactory;

public class ServiceLocator
{
  private static ServiceLocator me;
  
  private InitialContext context = null;
  private boolean propertiesLoaded = false;

    private ServiceLocator() throws ServiceLocatorException
  {
    try
    {
      context = new InitialContext();
//      context.addToEnvironment ( "weblogic.jndi.createIntermediateContexts", "true" );
    }
    catch(NamingException ne)
    {
      throw new ServiceLocatorException("Couldn't get InitialContext", ne);
    }
  }
  
  public synchronized static ServiceLocator getInstance() throws ServiceLocatorException
  {
    if (me==null) me=new ServiceLocator();
    return me;
  }
  
  /*public EJBObject getService(String id)  throws ServiceLocatorException {
    if (id == null)
      throw new ServiceLocatorException("Missing id in getService");
   
    try {
      byte[] bytes = new String(id).getBytes();
      InputStream io = new ByteArrayInputStream(bytes);
      ObjectInputStream os = new ObjectInputStream(io);
      javax.ejb.Handle handle = (javax.ejb.Handle)os.readObject();
      return handle.getEJBObject();
    } catch(Exception ex) {
      throw new ServiceLocatorException("Exception retrieving service id:" + id + " " + ex.getMessage());
    }
  }*/
  
  /*protected String getId(EJBObject session) throws ServiceLocatorException {
    try {
      javax.ejb.Handle handle = session.getHandle();
      ByteArrayOutputStream fo = new ByteArrayOutputStream();
      ObjectOutputStream so = new ObjectOutputStream(fo);
      so.writeObject(handle);
      so.flush();
      so.close();
      return new String(fo.toByteArray());
    } catch(RemoteException ex) {
      throw new ServiceLocatorException(ex.getMessage());
    } catch(IOException ex) {
      throw new ServiceLocatorException(ex.getMessage());
    }
   
  }*/
  
  public EJBHome getHome(String name, Class clazz)  throws ServiceLocatorException
  {
    try
    {
      Object objref = context.lookup(name);
      EJBHome home = (EJBHome) PortableRemoteObject.narrow(objref, clazz);
      return home;
    } catch(NamingException ex)
    {
      throw new ServiceLocatorException("Error getting Home", ex);
    }
  }

    public ConnectionFactory getConnectionFactory(String name)  throws ServiceLocatorException
    {
      try
      {
        Object objref = context.lookup("java:/" + name);
        // do i need to do this ??
        //ConnectionFactory cx = (ConnectionFactory) PortableRemoteObject.narrow(objref, clazz);
        return (ConnectionFactory) objref;
      } catch(NamingException ex)
      {
        throw new ServiceLocatorException("Error getting ConnectionFactory", ex);
      }
    }

    public LDAPJBDirContextFactory getLDAPJBDirContextFactory(String name)  throws ServiceLocatorException
    {
      try
      {
        Object objref = context.lookup("java:/" + name);
        // do i need to do this ??
        //ConnectionFactory cx = (ConnectionFactory) PortableRemoteObject.narrow(objref, clazz);
        return (LDAPJBDirContextFactory) objref;
      } catch(NamingException ex)
      {
        throw new ServiceLocatorException("Error getting LDAPJBDirContextFactory", ex);
      }
    }

    public CRLJBDirContextFactory getCRLJBDirContextFactory(String name)  throws ServiceLocatorException
    {
      try
      {
        Object objref = context.lookup("java:/" + name);
        // do i need to do this ??
        //ConnectionFactory cx = (ConnectionFactory) PortableRemoteObject.narrow(objref, clazz);
        return (CRLJBDirContextFactory) objref;
      } catch(NamingException ex)
      {
        throw new ServiceLocatorException("Error getting CRLJBDirContextFactory", ex);
      }
    }

    public OCSPJBDirContextFactory getOCSPJBDirContextFactory(String name)  throws ServiceLocatorException
    {
      try
      {
        Object objref = context.lookup("java:/" + name);
        // do i need to do this ??
        //ConnectionFactory cx = (ConnectionFactory) PortableRemoteObject.narrow(objref, clazz);
        return (OCSPJBDirContextFactory) objref;
      } catch(NamingException ex)
      {
        throw new ServiceLocatorException("Error getting OCSPJBDirContextFactory", ex);
      }
    }

  public String getProperty( String name )   //throws ServiceLocatorException
  {
    doFirstPropertiesLoading();
    try
    {
      return (String) lookup ( name );
    }
    catch ( ClassCastException cce )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error casting to String property:" + name, cce);
      return null;
    }
  }

  public Object lookup ( String name ) 
  {
    try
    {
      return context.lookup(name);
    }
    catch(NameNotFoundException ex)
    {
    }
    catch(Exception ex)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error getting object from JNDI:" + name, ex);
    }
    return null;
  }
  
  public void loadProperties( Properties props ) throws ServiceLocatorException
  {
    Enumeration keys = props.keys();
    while ( keys.hasMoreElements() )
    {
      try
      {
        String key = (String) keys.nextElement();
        String value = (String) props.getProperty(key);
        addProperty( key, value );
      }
      catch ( ClassCastException cce )
      {
        // loguear warning y continuar
        pkiva.log.LogManager.getLogger(this.getClass()).warn("Error loading property", cce);
      }
      catch(NamingException ex)
      {
        throw new ServiceLocatorException("Error binding property", ex);
      }
    } // end while
  }
  
  public synchronized void addProperty( String name, String value ) throws NamingException
  {
    StringBuffer debug = new StringBuffer("Adding property [");
    debug.append( name );
    debug.append( "," );
    debug.append( value );
    debug.append( "]" );
    pkiva.log.LogManager.getLogger(this.getClass()).debug(debug.toString());
    
    //context.bind( name, value );
    // diriarte - Changed to avoid NameAlreadyBoundException when changin' value just with redeploy
    context.rebind( name, value );
  }

  /*public int addProvider ( java.security.Provider p ) throws java.security.SecurityException
  {
    // removing first
    try
    {
      removeProvider(p.getName());
    }
    catch ( Throwable ignored )
    {
    }

    // adding
    return java.security.Security.addProvider(p);
  }

  public void removeProvider ( String name ) throws java.security.SecurityException
  {
    java.security.Security.removeProvider( name );
  }*/
  
    // diriarte: migration 2 jboss (properties matters)
        public Properties getPropAsResource(String name) throws Exception
        {
            InputStream is = getClass().getResourceAsStream(name);
            if (is == null)
            {
                throw new Exception("Unable to locate resource: " + name);
            }
            Properties confProp = new Properties();
            confProp.load(is);
            return confProp;
        }

    protected void doFirstPropertiesLoading()
    {
        if (!propertiesLoaded) {
            LDAPLoginConfiguration ldapLoginConfiguration = new LDAPLoginConfiguration();
            ldapLoginConfiguration.load();
            KeyStoreConfiguration keyStoreConfiguration = new KeyStoreConfiguration();
            keyStoreConfiguration.load();
            ValidationConfiguration validationConfiguration = new ValidationConfiguration();
            validationConfiguration.load();
            propertiesLoaded = true;
        }
    }

}
