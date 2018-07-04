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

import pkiva.exceptions.*;

public class TrustStore
{

  // ctes para acceso a DBTrustStore, package protected
  final static String BASE = "base";
  final static String QUALIFIER = "qualifier";
  final static String PRINCIPAL = "principal";
  final static String DPTYPE = "dptype";
  final static String CREDENTIALS = "credentials";
  final static String CREDENTIALS_TYPE = "credentialtype";

  // ctes para acceso a KeyTrustStore, package protected
  final static String KEYSTORE_NAME = "KeystoreName";
  final static String KEYSTORE_ALIAS = "KeystoreAlias";
  final static String KEYSTORE_TYPE = "KeystoreType";
  final static String KEYSTORE_PROVIDER = "KeystoreProvider";

  protected Hashtable parameters;

  protected TrustStore ()
  {
    parameters = new Hashtable ();
  }

  public void setParameters ( Hashtable t )
  {
    this.parameters = t;
  }

  public String getPlainPassword ( ) throws TrustStoreException
  {
    throw new TrustStoreException ( new MethodNotSupportedException ( ) );
  }

  public X509Certificate getCertificate ( ) throws TrustStoreException
  {
    throw new TrustStoreException ( new MethodNotSupportedException ( ) );
  }

  public PrivateKey getPrivKey ( ) throws TrustStoreException
  {
    throw new TrustStoreException ( new MethodNotSupportedException ( ) );
  }
}
