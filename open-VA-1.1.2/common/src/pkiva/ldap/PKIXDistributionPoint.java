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

import java.io.*;
import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import java.security.*;
import java.security.cert.*;

import pkiva.validation.crl.*;

/**
 *
 * @author  diriarte
 */
public abstract class PKIXDistributionPoint implements Comparable
{
  
  // String y no int para que sirvan como keys de Hashtable y ademas de comparacion con el value del attribute
  public static final String PKIXCRLDP = "pkixCRLDistributionPoint";
  public static final String PKIXOCSPDP = "pkixOCSPDistributionPoint";
  
  protected String uri;
  protected int dpPriority;
  protected String type;
  protected String crlType;
  protected Attributes atts;
  
  /** Creates a new instance of PKIXDistributionPoint */
  protected PKIXDistributionPoint( String uri, int pri, String type)
  {
    this ( uri, pri, type, null );
  }

  /** Creates a new instance of PKIXDistributionPoint */
  protected PKIXDistributionPoint( String uri, int pri, String type, String crlType)
  {
    this.uri = uri;
    this.dpPriority = pri;
    this.type = type;
    this.crlType = crlType;
    this.atts = new BasicAttributes();
  }
  
  public int compareTo(Object o)
  {
    PKIXDistributionPoint another = (PKIXDistributionPoint) o;
    return this.dpPriority - another.dpPriority;
  }
  
  public String toString()
  {
    StringBuffer out = new StringBuffer( type )
      .append( ":[ " ).append ( uri ).append( ", " ).append( dpPriority ).append( " ]" );
    
    return out.toString() ;
  }
  
  public static PKIXDistributionPoint getPKIXDistributionPoint( SearchResult result )
  {
    String uri = LDAPUtils.extractAttributeValue( LDAPUtils.removeQuotes( result.getName() ) );
    // we should decode URIs
    uri = LDAPUtils.decode ( uri ); // decode doesn't throw Exception

    int pri = getDPPriority( result );
    String type = getStringAttribute ( result, "objectClass");
    String crlType = getStringAttribute ( result, "dpType");
    if ( crlType == null )
      crlType = IssuingDistributionPoint.DEFAULT_DPTYPE;
    
    PKIXDistributionPoint object2Return = null;
    // TODO: pensar en optimizar esto
    // pbma: el nombre del tipo en ldap esta en lower, y en Java en upper
    if ( PKIXCRLDP.equals( type ) )
      object2Return = new PKIXCRLDistributionPoint( uri, pri, crlType );
    else if ( PKIXOCSPDP.equals( type ) )
      object2Return = new PKIXOCSPDistributionPoint( uri, pri );
    else
    {
      // warning: el tipo del objeto no es reconocido:
      StringBuffer log = new StringBuffer( "Found CN:" )
      .append (result.getName())
      .append ( "Not matching any PKIXDistributionPoint.Type:" )
      .append ( type );
      pkiva.log.LogManager.getLogger("PKIXDistributionPoint").warn( log.toString() );
    }

    if ( object2Return != null )
    {
      object2Return.setAttributes ( result.getAttributes() );
    }
    
    return object2Return;
  }
  
  // en caso de error devolvemos un numero alto para que no se elija por prioridad
  private static int getDPPriority( SearchResult result )
  {
    Attributes attrs = result.getAttributes();
    try
    {
      String value = (String) LDAPUtils.getAttributeValue(attrs, "dppriority");
      return Integer.parseInt( value );
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger("PKIXDistributionPoint").error( "getting DPPriority attribute", t);
      return Integer.MAX_VALUE;
    }
  }
  
  protected static String getStringAttribute ( SearchResult result, String attName )
  {
    Attributes attrs = result.getAttributes();
    try
    {
      return (String) LDAPUtils.getAttributeValue(attrs, attName);
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger("PKIXDistributionPoint").error( "getting attribute " + attName, t);
      return null;
    }
  }
  
  /** devuelve, si existe, el certificado del elemento que figura como atributo con nombre 'cacertificate'
   * shortcut a cogerlo de los atributos
   */
  public X509Certificate getCACertificate( )
  {
    try
    {
      Object value = LDAPUtils.getAttributeValue(atts, "cacertificate;binary");
      if ( !( value instanceof byte[] ) )
        return null; // attribute value is not binary
      
      return EstructuralElement.getCert( (byte[]) value );
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error( "getting Certificate from DP", t );
      return null;
    }
  }

  public String getKsAlias ( )
  {
    try
    {
      return (String) LDAPUtils.getAttributeValue(atts, "ksAlias");
    }
    catch ( NameNotFoundException e )
    {
      return null;
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error( "getting Certificate from DP", t );
      return null;
    }
  }
  
  /** Getter for property uri.
   * @return Value of property uri.
   *
   */
  public java.lang.String getUri()
  {
    return uri;
  }
  
  /** Getter for property dpPriority.
   * @return Value of property dpPriority.
   *
   */
  public int getDpPriority()
  {
    return dpPriority;
  }
  
  /** Getter for property type.
   * @return Value of property type.
   *
   */
  public String getType()
  {
    return type;
  }
  
  /** Getter for property crlType.
   * @return Value of property crlType.
   *
   */
  public String getCRLType()
  {
    return crlType;
  }

  /** Getter for property atts.
   * @return Value of property atts.
   *
   */
  public Attributes getAttributes()
  {
    return atts;
  }

  public void setAttributes ( Attributes newAtts )
  {
    this.atts = newAtts;
  }
  
}
