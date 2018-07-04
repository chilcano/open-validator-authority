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
package pkiva.trustStore;

import java.util.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
/*import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;*/

import pkiva.services.*;
import pkiva.exceptions.*;
import pkiva.management.startup.*;

public class TrustStoreManager
{ //Singleton
  
  static private TrustStoreManager instance = new TrustStoreManager();
  
  static public TrustStoreManager getInstance()
  {
    return instance;
  }
  
  protected TrustStoreManager()
  {
  }

  private static final String GET_PLAIN_PWD = "getPlainPassword";
  private static final String GET_CERTIFICATE = "getCertificate";
  private static final String GET_PRIV_KEY = "getPrivKey";
  
  public String getPlainPassword ( String base, String qualifier, String principal, String dpType ) throws TrustStoreException
  {
    // TODO: obtener instancia basada en properties, no por codigo
    TrustStore trustStore = getSuitableTrustStore (  GET_PLAIN_PWD );

    // construir parametros
    Hashtable params = new Hashtable ();
    try
    {
      if ( base != null )
        params.put ( TrustStore.BASE , base);
      if ( qualifier != null )
        params.put ( TrustStore.QUALIFIER , qualifier);
      if ( principal != null )
        params.put ( TrustStore.PRINCIPAL , principal);
      if ( dpType != null )
        params.put ( TrustStore.DPTYPE , dpType );
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Construyendo parametros para getPlainPassword", t);
      throw new TrustStoreException ( t );
    }
    trustStore.setParameters ( params );

    // llamar a la instancia
    return trustStore.getPlainPassword ( );
  }

  public X509Certificate getCertificate ( String keyStoreAlias ) throws TrustStoreException
  {
    // TODO: obtener instancia basada en properties, no por codigo
    TrustStore trustStore = getSuitableTrustStore (  GET_CERTIFICATE );

    // construir parametros
    trustStore.setParameters ( getKeyStoreParams ( keyStoreAlias ) );

    // llamar a la instancia
    return trustStore.getCertificate ( );
  }

  public PrivateKey getPrivKey ( String keyStoreAlias ) throws TrustStoreException
  {
    // TODO: obtener instancia basada en properties, no por codigo
    TrustStore trustStore = getSuitableTrustStore (  GET_PRIV_KEY );

    // construir parametros
    trustStore.setParameters ( getKeyStoreParams ( keyStoreAlias ) );

    // llamar a la instancia
    return trustStore.getPrivKey ( );
  }

  protected Hashtable getKeyStoreParams ( String alias ) throws TrustStoreException
  {
    Hashtable params = new Hashtable ();

    try
    {
      String keyStoreName = ServiceLocator.getInstance().getProperty( KeyStoreConfiguration.KEYSTORE_NAME );
      String keyStoreType = ServiceLocator.getInstance().getProperty( KeyStoreConfiguration.KEYSTORE_TYPE );
      String keyStoreProvider = ServiceLocator.getInstance().getProperty( KeyStoreConfiguration.KEYSTORE_PROVIDER );

      pkiva.log.LogManager.getLogger(this.getClass()).debug( "Using keyStoreName:" + keyStoreName );
      pkiva.log.LogManager.getLogger(this.getClass()).debug( "Using keyStoreType:" + keyStoreType );
      pkiva.log.LogManager.getLogger(this.getClass()).debug( "Using keyStoreProvider:" + keyStoreProvider );

      params.put ( TrustStore.KEYSTORE_NAME , keyStoreName);
      params.put ( TrustStore.KEYSTORE_ALIAS , alias);
      params.put ( TrustStore.KEYSTORE_TYPE , keyStoreType);
      params.put ( TrustStore.KEYSTORE_PROVIDER , keyStoreProvider);
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Construyendo parametros para getCertificate", t);
      throw new TrustStoreException ( t );
    }

    return params;
  }

  protected TrustStore getSuitableTrustStore ( String operation ) throws TrustStoreException
  {
    if ( GET_PLAIN_PWD.equals ( operation ) )
    {
      return new DBTrustStore();
    }
    else if ( GET_CERTIFICATE.equals ( operation ) )
    {
      return new KeyTrustStore();
    }
    else if ( GET_PRIV_KEY.equals ( operation ) )
    {
      return new KeyTrustStore();
    }
    /*else if ( .equals ( operation ) )
    {
      return new 
    }*/
    else
    {
      throw new TrustStoreException ( "TrustStore not found for operation:" + operation );
    }
  }

}
