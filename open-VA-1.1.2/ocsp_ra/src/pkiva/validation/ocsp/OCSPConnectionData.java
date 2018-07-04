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
package pkiva.validation.ocsp;

import java.security.cert.*;
import java.security.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.util.*;

import pkiva.providers.*;
import pkiva.exceptions.*;
import pkiva.ldap.*;
import pkiva.trustStore.*;

public class OCSPConnectionData 
{
  // datos de la cadena a validar
  protected X509Certificate[] chain;
  protected int len;

  // datos del LDAP
  protected EstructuralElement ca;
  protected List ocspList;
  protected String alias;

  // path.length >= 1
  public OCSPConnectionData (  X509Certificate[] path ) throws OCSPValidationException
  {
    this.chain = path;
    len = chain.length;

    ca = getCAForChain();
    pkiva.log.LogManager.getLogger(this.getClass()).debug("CA correspondiente al certificado: " + ca);
    if ( ca == null )
      throw new OCSPValidationException( "No CA element in store for certificate");

    ocspList = ca.getDistributionPoints( PKIXDistributionPoint.PKIXOCSPDP );
    pkiva.log.LogManager.getLogger(this.getClass()).debug("OCSP list correspondiente al certificado: " + ocspList);
    if ( ( ocspList == null ) || (ocspList.size() == 0 ) )
      throw new OCSPValidationException( "No OCSP distribution point in CA element for certificate");

    this.alias = null;
  }

  public X509Certificate getSignCert( ) throws TrustStoreException, OCSPValidationException
  {
    // get KeyStore alias from ldap
    String keyStoreAlias = getKsAlias ( );

    if ( keyStoreAlias == null )
      // if there is no alias, don't sign request
      //throw new OCSPValidationException( "No KeyStore alias in OCSP distribution point for certificate");
      return null;

    // get Certificate from TrustStoreManager
    return TrustStoreManager.getInstance().getCertificate( keyStoreAlias );
  }
  
  public PrivateKey getSignKey( ) throws TrustStoreException, OCSPValidationException
  {
    // get KeyStore alias from ldap
    String keyStoreAlias = getKsAlias ( );

    if ( keyStoreAlias == null )
      // if there is no alias, don't sign request
      //throw new OCSPValidationException( "No KeyStore alias in OCSP distribution point for certificate");
      return null;

    // get Priv Key from TrustStoreManager
    return TrustStoreManager.getInstance().getPrivKey( keyStoreAlias );
  }
  
  public String getURL( )
  {
    String uri = null;

    //int size = ocspList.size();
    //for ( int i = 0; i<size ; i++ )
    {
      //PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(i);
      PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(0);
      uri = dp.getUri();
      if ( uri != null )
        return uri;
    }

    return null;
  }
  
  public X509Certificate getResponderCert( )
  {
    X509Certificate cert = null;

    //int size = ocspList.size();
    //for ( int i = 0; i<size ; i++ )
    {
      //PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(i);
      PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(0);
      cert = dp.getCACertificate();
      if ( cert != null )
        return cert;
    }

    return null;
  }
  
  public String getSigningAlgorithm( )
  {
    return "MD5WITHRSA";
  }
  
  public String getProvider( )
  {
    return "BC";
  }
  
  protected EstructuralElement getCAForChain() {
    // todo hacerlo recursivo para cada uno de los padres si no encontramos para la ICA
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Retrieving CA for chain.");
    Set s = CertStoreProvider.getCAEstructuralElements();
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Retrieving CA for chain.Iterating in elements #:" + s.size());

    X500Principal certIssuer = chain[len-1].getIssuerX500Principal();
    X509CertSelector selector = new X509CertSelector();
    try
    {
      // add the default issuer string
      selector.setSubject(certIssuer.getName("RFC2253"));
    }
    catch ( IOException ioe )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Can't set certificate Issuer name for selector", ioe);
      return null;
      // TODO: intentarlo por el nombre del ldap ??
    }


    for(Iterator it=s.iterator();it.hasNext();)
    {
        EstructuralElement elm = (EstructuralElement) it.next();
        X509Certificate cert = elm.getCACertificate();
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Iterating in cert (subj): " + cert.getSubjectDN());
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Iterating in cert (issu): " + cert.getIssuerDN());
        if ( ( cert != null ) && (selector.match(cert)) )
          return elm;
    }

    pkiva.log.LogManager.getLogger(this.getClass()).warn("Not found CA for chain");
    return null;
  }

  protected String getKsAlias ( )
  {
    if ( this.alias != null)
      return this.alias;
    
    String ldapAlias = null;

    //int size = ocspList.size();
    //for ( int i = 0; i<size ; i++ )
    {
      //PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(i);
      PKIXDistributionPoint dp = (PKIXDistributionPoint) ocspList.get(0);
      ldapAlias = dp.getKsAlias();
      if ( ldapAlias != null )
      {
        this.alias = ldapAlias;
        return ldapAlias;
      }
    }

    return null;
  }

}
