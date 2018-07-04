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
import java.net.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

/** CLase con utilidades relacionadas con LDAP
 *
 * @author  diriarte
 */
public class LDAPUtils
{
  public static void printHash( Hashtable t )
  {
    printCollection ( 0, t.values() );
  }
  
  public static void printCollection( int indentLevel, Collection t )
  {
    printCollection ( indentLevel, t, true );
  }
  
  public static void printCollection( int indentLevel, Collection t, boolean doRecurse )
  {
    StringBuffer tabsSB = new StringBuffer ();
    for ( int i = 0; i < indentLevel; i++ )
      tabsSB.append ( '\t' );
    String tabs = tabsSB.toString();
    
    Iterator iter = t.iterator();
    while ( iter.hasNext() )
    {
      EstructuralElement value = (EstructuralElement) iter.next();
      System.out.print( tabs );
      System.out.println( value.toString ( tabs) );
      if ( doRecurse )
        printCollection ( indentLevel + 1, value.collectCAs ( false ) );
      System.out.println( );
    }
  }
  
  public static Object getAttributeValue( Attributes attrs, String attName ) throws NamingException
  {
    if ( attrs == null )
      return null;
    
    Attribute att = attrs.get( attName );
    if ( att == null )
      return null;
    
    return att.get();
  }

  /** dada una frase del tipo "o=e-xtendnow S.R.L" o "ou=Banco de Sabadell Class 2 CA"
   * devuelve "e-xtendnow S.R.L" o "Banco de Sabadell Class 2 CA" */
  public static String extractAttributeValue ( String in )
  {
    StringTokenizer tok = new StringTokenizer( in, "=" );
    String out = in;
    if (tok.hasMoreElements())
    {
      // desechamos el nombre del atributo ("o", "ou", ... )
      tok.nextElement();
      if (tok.hasMoreElements())
      {
        // aqui viene el segundo, es el nombre completo
        out = tok.nextToken();
        // TODO: y si en el nombre hay algun caracter '=' ??
        // iterar y concatenar la frase resultante
      }
    }
    return out;
  }

  protected static String decode ( String url )
  {
    try
    {
      return URLDecoder.decode ( url, "UTF-8" );
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger("LDAPUtils").error("Error decoding string:" + url, e);
      return url;
    }
  }
  
  protected static String encode ( String url )
  {
    try
    {
      return URLEncoder.encode ( url, "UTF-8" );
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger("LDAPUtils").error("Error encoding string:" + url, e);
      return url;
    }
  }


  
  /** dada una frase del tipo ["cn=http://pilotonsitecrl.ace.es/extendnowITClass3/LatestCRL.crl"]
   * devuelve [cn=http://pilotonsitecrl.ace.es/extendnowITClass3/LatestCRL.crl] */
  public static String removeQuotes ( String in )
  {
    if ( ( in == null ) || ( in.length() == 0 ) )
      return ""; // evitaremos nullPointers en caso de desconfiguracion
    
    int length = in.length();
    int from = 0;
    int to = length;
    
    if ( isQuote ( in.charAt ( 0 ) ) )
      from = 1;
    if ( isQuote ( in.charAt ( length - 1 ) ) )
      to -= 1;
    
    if ( ( from == 0 ) && ( to == length ) )
      return in;
    else
      return in.substring( from, to );
  }
  
  private static boolean isQuote ( char c )
  {
    return ( c == '"') || ( c == '\'' );
  }
  

}
