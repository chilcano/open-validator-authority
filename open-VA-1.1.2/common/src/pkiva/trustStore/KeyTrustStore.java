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

import java.io.*;
import java.util.*;
import java.sql.*;
import javax.sql.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import pkiva.exceptions.*;
import pkiva.services.*;
import pkiva.validation.crl.*;

public class KeyTrustStore extends TrustStore
{
  static protected final String KEYSTORE_PRINCIPAL = "keystore";

  public KeyTrustStore()
  {
    super();
    /*try
    {
      keyStoreType = ServiceLocator.getInstance().getProperty( KeyStoreConfiguration.KEYSTORE_TYPE );
      keyStoreProvider = ServiceLocator.getInstance().getProperty( KeyStoreConfiguration.KEYSTORE_PROVIDER );
      pkiva.log.LogManager.getLogger(this.getClass()).debug( "Using keyStoreType:" + keyStoreType );
      pkiva.log.LogManager.getLogger(this.getClass()).debug( "Using keyStoreProvider:" + keyStoreProvider );
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error( "Error getting keyStoreType & keyStoreProvider properties", e );
    }*/
  }
  
  public X509Certificate getCertificate ( ) throws TrustStoreException
  {
    try
    {
      // get Parameters
      // in
      String keyStoreName = (String) parameters.get( KEYSTORE_NAME );
      String keyStoreType = (String) parameters.get( KEYSTORE_TYPE );
      String keyStoreProvider = (String) parameters.get( KEYSTORE_PROVIDER );
      String alias = (String) parameters.get( KEYSTORE_ALIAS );
      String password = getKeyStorePassword ( keyStoreName );

      KeyStore ks = getKeyStore ( keyStoreName, password, keyStoreType, keyStoreProvider );

      return (X509Certificate) ks.getCertificate(alias);
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error getting Priv Key", e);
      throw new TrustStoreException ("Error getting Priv Key", e);
    }
  }

  public PrivateKey getPrivKey ( ) throws TrustStoreException
  {
    try
    {
      // get Parameters
      // in
      String keyStoreName = (String) parameters.get( KEYSTORE_NAME );
      String alias = (String) parameters.get( KEYSTORE_ALIAS );
      String keyStoreType = (String) parameters.get( KEYSTORE_TYPE );
      String keyStoreProvider = (String) parameters.get( KEYSTORE_PROVIDER );
      String password = getKeyStorePassword ( keyStoreName );

      KeyStore ks = getKeyStore ( keyStoreName, password, keyStoreType, keyStoreProvider );

      return (PrivateKey) ks.getKey(alias, null);
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error getting Priv Key", e);
      throw new TrustStoreException ("Error getting Priv Key", e);
    }
  }

  protected static String getKeyStorePassword ( String keyStoreName ) throws TrustStoreException
  {
    return TrustStoreManager.getInstance().getPlainPassword ( keyStoreName, null, KEYSTORE_PRINCIPAL, null);
  }

  protected static KeyStore getKeyStore ( String ksname, String kspwd, String keyStoreType, String keyStoreProvider ) throws Exception
  {
    KeyStore ks = KeyStore.getInstance(keyStoreType, keyStoreProvider);
    ks.load( getKSStream(ksname), kspwd == null ? null : kspwd.toCharArray());
    return ks;
  }

  protected static InputStream getKSStream ( String ksname ) throws IOException
  {
    // TODO: adaptar para otros casos, no solo disco.
    return new FileInputStream ( ksname );
  }
}
