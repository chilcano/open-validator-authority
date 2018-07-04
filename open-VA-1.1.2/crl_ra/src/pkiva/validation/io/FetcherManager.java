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
import java.security.cert.X509CRL;
import java.lang.reflect.*;
import javax.naming.*;
import javax.naming.directory.*;
import pkiva.log.*;
import pkiva.log.operations.*;
import pkiva.exceptions.*;

public class FetcherManager
{ //Singleton
  
  static private FetcherManager m_instance=new FetcherManager();
  
  static public FetcherManager instance()
  {
    return m_instance;
  }
  
  protected FetcherManager()
  {
  }
  
  public X509CRL getCRL( String location ) throws FetchingException
  {
    return getCRL ( location, new Properties() );
  }
  
  public X509CRL getCRL( String location, Attributes atts ) throws FetchingException
  {
    return getCRL ( location, attributes2Properties ( atts ) );
  }
  
  public X509CRL getCRL( String location, Properties props ) throws FetchingException
  {
    CRLInstall auditOper = new CRLInstall ();
    auditOper.setURL ( location );
    try
    {
      Class c = resolveClass( location );
      if ( c == null )
        return null;

      GenericFetcher fetcher = getFetcher( c, location, props );
      X509CRL crl = fetcher.getCRL( );
      if ( crl == null )
      {
        pkiva.log.LogManager.getLogger(this.getClass()).warn("Couldn't fetch CRL from location: " + location);
      }
      else
      {
        /*StringBuffer msg = new StringBuffer ("Fetched CRL from location: ");
        msg.append(location).append(":\n").append(crl);
        String msgSt = msg.toString();
        pkiva.log.LogManager.getLogger(this.getClass()).info(msgSt);
        pkiva.log.AuditManager.getAuditer(this.getClass()).audit(msgSt);*/
        auditOper.setCRL ( crl );
        pkiva.log.AuditManager.getAuditer(this.getClass()).audit(auditOper);
      }
      return crl;
    }
    catch ( FetchingException fe )
    {
      auditOper.setError ( fe );
      audit ( auditOper );
      throw fe;
    }
    catch ( Exception e )
    {
      auditOper.setError ( e );
      audit ( auditOper );
      throw new FetchingException ( "Internal error fetching CRL from location: " + location, e);
    }
    
  }

  private void audit ( AuditOperation auditOper ) throws FetchingException
  {
    try
    {
      pkiva.log.AuditManager.getAuditer(this.getClass()).audit(auditOper);
    }
    catch ( AuditingException ae )
    {
      throw new FetchingException ( "Internal error auditing: ", ae);
    }
  }
  
  private Class resolveClass( String location ) throws FetchingException
  {
    // TODO: resolve className with properties file ??
    String protocol = getProtocolName(location);
    if ( protocol == null)
      return null;
    
    protocol = protocol.toUpperCase();
    StringBuffer classNameSB = new StringBuffer("pkiva.validation.io.")
    .append( protocol )
    .append( "Fetcher" );
    
    try
    {
      return Class.forName( classNameSB.toString() );
    }
    catch ( ClassNotFoundException cnfe )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Protocol not supported for uri: " + location, cnfe);
      throw new FetchingException( "Protocolo " + protocol + " not supported", cnfe );
    }
  }
  
  private GenericFetcher getFetcher( Class classDefinition, String location, Properties props ) throws FetchingException
  {
    try
    {
      Class[] argsclass=new Class[]
      {String.class , Properties.class};
      Object[] args=new Object[]
      {location,props};
      Constructor cons=classDefinition.getConstructor(argsclass);
      GenericFetcher obj=(GenericFetcher) cons.newInstance(args);
      return obj;
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error in Instance: " + classDefinition.getName(), e);
      throw new FetchingException( "Error in Instance " + classDefinition.getName(), e );
    }
  }
  
  private static String getProtocolName(String strUri)
  {
    int i=strUri.indexOf(":");
    if ( i < 0 )
      return null;
    return strUri.substring(0,i);
  }

  protected static Properties attributes2Properties ( Attributes atts )
  {
    Properties props = new Properties();

    if ( atts != null )
    {
      try
      {
        NamingEnumeration en = atts.getIDs();
        while ( en.hasMoreElements() )
        {
          String name = (String) en.nextElement();
          try
          {
            Attribute att = atts.get(name) ;
            String value = (String) att.get();
            props.setProperty ( name, value );
          }
          catch ( Exception e)
          {
            pkiva.log.LogManager.getLogger("FetcherManager").error("Error translating into Properties, attibute: " + name, e);
          }
        } // end while
      }
      catch ( Exception e)
      {
        pkiva.log.LogManager.getLogger("FetcherManager").error("Error translating into Properties, attibutes: " + atts, e);
      }

    } // end if

    return props;
  }
  
}
