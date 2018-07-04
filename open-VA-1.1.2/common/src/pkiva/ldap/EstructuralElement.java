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

public class EstructuralElement
{
  
  protected String distinguishedName;
  protected String name;
  protected boolean ca;
  protected boolean org;
  protected Attributes attrs;
  
  // guardaremos aqui los elementos hijos, con su nombre como key para optimizar busquedas
  protected Hashtable elements;
  
  // guardaremos aqui los dps ordenados por prioridad
  protected List dps;
  
  private static final String NEW_LINE = System.getProperty( "line.separator" );
  
  protected EstructuralElement()
  {
    elements = new Hashtable();
    dps = new Vector();
  }
  
  /** devuelve todos los elementos (o & ou) que cuelgan de este (sean CAs o no), no recursivamente */
  public Collection getElements( )
  {
    return getChildren( false, false);
  }
  
  /** devuelve las CAs que cuelgan de este elemento, recursivamente */
  public Collection collectCAs( )
  {
    return collectCAs( true );
  }
  
  /** devuelve las CAs que cuelgan de este elemento
   * si recurse no es true solo devolvera las de primer nivel */
  public Collection collectCAs( boolean recurse )
  {
    return getChildren( true, recurse);
  }
  
  /** devuelve todos los elementos (o & ou) que cuelgan de este
   * puede coger solo las CAs (onlyCAs == true) o todos los elementos (ioc)
   * recursivo o no, segun el segundo parametro */
  protected Collection getChildren( boolean onlyCAs, boolean recurse )
  {
    Collection candidates = elements.values(); // tenemos aqui las de primer nivel
    Collection result = new Vector(); // aqui iremos metiendo las que matcheen
    
    // Iteramos en todos los candidatos
    Iterator iter = candidates.iterator();
    while ( iter.hasNext() )
    {
      EstructuralElement el = (EstructuralElement) iter.next();
      
      // filtramos solo las CAs si asi nos indican
      if ( ( !onlyCAs ) || ( el.isCA() ) )
        result.add( el );
      
      if ( recurse )
        result.addAll( el.getChildren( onlyCAs, recurse ) );
    }
    
    return result;
    
  }
  
  /** devuelve el elemento con el nombre dado que cuelga directamente (no recursivo) de este elemento */
  public EstructuralElement getElement( String name )
  {
    return (EstructuralElement ) elements.get( name );
  }
  
  /** devuelve lista ordenada por prioridades (mas proritarios primero) de distribution points */
  public List getDistributionPoints( )
  {
    return dps;
  }
  
  /** devuelve lista ordenada por prioridades (mas proritarios primero) de distribution points
   que sean del tipo especificado */
  public List getDistributionPoints( String type )
  {
    List typedDps = new Vector();
    
    Iterator iter = dps.iterator();
    while ( iter.hasNext() )
    {
      PKIXDistributionPoint dp = (PKIXDistributionPoint) iter.next();
      
      if ( dp.getType().equals( type) )
        typedDps.add( dp );
    }
    
    return typedDps;
    
  }
  
  /** devuelve el tipo del DistributionPoint mas prioritario */
  public String getDistributionPointType( )
  {
    String type = null;

    if ( dps.size() > 0 )
    {
      PKIXDistributionPoint dp = (PKIXDistributionPoint) dps.get( 0 );
      type = dp.getType ();
    }

    return type;
  }
  

  public String toString()
  {
    return toString( "" );
  }
  
  public String toString( String indent )
  {
    StringBuffer out = new StringBuffer( "EstructuralElement:[" )
    //StringBuffer out = new StringBuffer ( "[" )
    .append( getName() );
    
    if ( isCA() )
      out.append( ", CA" );
    if ( isOrg() )
      out.append( ", Organization" );
    
    out.append( "]" ).append( NEW_LINE ).append( indent );
    
    // Attributes
    out.append( "\tAttributes:" ).append( attrs ).append( NEW_LINE ).append( indent );
    
    // Attributes
    out.append( "\tDPs:" ).append( dps );
    
    return out.toString() ;
  }
  
  /** Getter for property distinguishedName.
   * @return Value of property distinguishedName.
   *
   */
  public java.lang.String getDistinguishedName()
  {
    return distinguishedName;
  }
  
  /** Getter for property name.
   * @return Value of property name.
   *
   */
  public java.lang.String getName()
  {
    return name;
  }
  
  /** Getter for property org.
   * @return Value of property org.
   *
   */
  public boolean isOrg()
  {
    return org;
  }
  
  /** Getter for property ca.
   * @return Value of property ca.
   *
   */
  public boolean isCA()
  {
    return ca;
  }
  
  /** Getter for property attrs.
   * @return Value of property attrs.
   *
   */
  public javax.naming.directory.Attributes getAttrs()
  {
    return attrs;
  }
  
  /** devuelve, si existe, el attribute asociado al nombre especificado, null si no existe.
   * shorcut to this.getAttrs().get( name )
   */
  public javax.naming.directory.Attribute getAttribute( String name )
  {
    return this.getAttrs().get( name );
  }
  
  /** devuelve, si existe, el certificado del elemento que figura como atributo con nombre 'cacertificate'
   * shortcut a cogerlo de los atributos
   */
  // TODO: devolver una collection ??
  public X509Certificate getCACertificate( )
  {
    try
    {
      Object value = LDAPUtils.getAttributeValue(attrs, "cacertificate;binary");
      if ( !( value instanceof byte[] ) )
        return null; // attribute value is not binary
      
      return getCert( (byte[]) value );
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error( "getting Certificate from CA", t );
      return null;
    }
  }
  
  // ------------ package protected methods, no se deberian usar desde fuera (?) ---------------------
  // debido al cambio de esta clase al APP-INF para que se vea desde los EJBs, han de ser publics
  // porque esta en distinto ClassLoader (?)
  
  /** anyade los elementos de la hash como hijos
   */
  public void addChildren( Hashtable children )
  {
    elements.putAll( children );
  }
  
  /** anyade los dps de la lista y ordena la lista resultante
   */
  public void addDPs( List newDps )
  {
    dps.addAll( newDps );
    // ordenamos segun la prioridad y guardamos una lista ordenada ...
    Collections.sort( dps );
  }
  
  // ------------ metodo estatico para crear el objeto ---------------------
  
  /** crea un EstructuralElement a partir de un elemento de resultado de una busqueda
   */
  public static EstructuralElement getEstructuralElement( SearchResult result )
  {
    EstructuralElement estElm = new EstructuralElement();
    
    estElm.distinguishedName = result.getName();
    
    // TODO: comprobar si estos attributes se pueden recoger despues de cerrar la conexion.
    // si no fuera asi, se habria de recoger aqui tb el certificate (y lo demas que venga ?) y almacenarlo en el objeto.
    estElm.attrs = result.getAttributes();  // Returns: The non-null attributes in this search result. Can be empty.
    estElm.ca = isCA( estElm.attrs );
    estElm.org = isOrganization( estElm.attrs );
    
    // estElm.distinguishedName -> "o=e-xtendnow S.R.L", "ou=Banco de Sabadell Class 2 CA"
    String name = LDAPUtils.extractAttributeValue( estElm.distinguishedName );
    
    if ( name == null )
      estElm.name = result.getName();
    else
      estElm.name = name;
    
    return estElm;
  }
  
  // ------------ metodos privados estaticos para ayuda ---------------------
  
  private static boolean isCA( Attributes attrs )
  {
    return isValue( attrs, "objectClass", "pkiCA" );
  }
  
  private static boolean isOrganization( Attributes attrs )
  {
    return isValue( attrs, "objectClass", "organization" );
  }
  
  private static boolean isValue( Attributes attrs, String attribute, String value )
  {
    if ( attrs != null )
    {
      Attribute attr = attrs.get(attribute);
      if ( attr != null )
        return attr.contains(value);
      else
        return false;
    }
    else
      return false;
  }
  
  public static X509Certificate getCert( byte[] bytes )  throws CertificateException, IOException
  {
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate)cf.generateCertificate(bais);
    bais.close();
    return cert;
  }
  
  
}
