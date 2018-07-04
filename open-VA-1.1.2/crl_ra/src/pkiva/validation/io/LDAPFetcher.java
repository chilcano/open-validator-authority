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
package pkiva.validation.io;

import java.util.Properties;
import java.security.cert.*;
import java.io.*;
import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import pkiva.ldap.*;
import pkiva.ldap.login.*;
import pkiva.management.startup.*;
import pkiva.services.*;
import pkiva.exceptions.*;
import pkiva.trustStore.*;

public class LDAPFetcher extends GenericFetcher
{

  protected String directory;
  protected String qualifier;
  
  public LDAPFetcher(String loc, Properties props)
  {
    super( loc, props );
    parseLocation ( );
  }
  
  public X509CRL getCRL() throws FetchingException
  {
    if ( ( directory == null) || ( qualifier == null) )
    {
      throw new FetchingException( "Malformed URL:" + location );
    }

    InitialLdapContext context = null;
    try
    {
      Hashtable ldapParams = getLDAPParams ();
      UserPassLoginModule loginModule = new UserPassLoginModule ( ldapParams );
      context = loginModule.getContext();

      if ( context == null )
      {
        throw new FetchingException( "Could not establish connection to:" + directory);
      }

      Attributes  atts = context.getAttributes( location );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Attributes:" + atts);

      return getCRLFromAttributes ( atts );
    }
    catch ( Exception e )
    {
      throw new FetchingException( "Error getting CRL via LDAP.", e );
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
  
  private InputStream getSuitableInputStream( ) throws IOException
  {
    return new HTTPInputStream( location, params );
  }

  private void parseLocation ( )
  {
    if ( ! location.startsWith ( "ldap://" ) )
    {
      location += "ldap://";
    }
    
    int urlEnd = location.indexOf ( "/", 7); //  skipping ("ldap://")
    if ( urlEnd < 7 )
    {
      // malformed URL
      pkiva.log.LogManager.getLogger(this.getClass()).error("Malformed URL:" + location);
      directory = null;
      qualifier = null;
    }
    else
    {
      directory = location.substring ( 0, urlEnd );
      qualifier = location.substring ( urlEnd + 1 );
    }
    pkiva.log.LogManager.getLogger(this.getClass()).debug("parseLocation directory:" + directory);
    pkiva.log.LogManager.getLogger(this.getClass()).debug("parseLocation qualifier:" + qualifier);
  }

  protected Hashtable getLDAPParams ( )
  {
    Hashtable ht = new Hashtable ();

    ht.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory"  );
    ht.put( Context.PROVIDER_URL, directory );

    String principal = (String) params.get("principal");
    if ( principal != null )
      ht.put( Context.SECURITY_PRINCIPAL, principal );

    String credentials = null;
    try
    {
      String dpType = (String) params.get("dpType");
        
      credentials = TrustStoreManager.getInstance().getPlainPassword( directory,  qualifier,  principal,  dpType);
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Could not get credentials from properties:" + params, e);
    }

    if ( credentials != null )
      ht.put( Context.SECURITY_CREDENTIALS, credentials );
    
    return ht;

  }

  protected static X509CRL getCRLFromAttributes ( Attributes atts ) throws Exception
  {
    byte[] crlData = (byte[]) LDAPUtils.getAttributeValue ( atts, "certificateRevocationList;binary");

    InputStream inStream = new ByteArrayInputStream(crlData);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509CRL crl = (X509CRL)cf.generateCRL(inStream);
    inStream.close();

    return crl;
  }

}
