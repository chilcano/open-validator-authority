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

/**
 *
 * @author  diriarte
 */
public class LDAPModel implements Comparable
{
  
  // Datos del LDAP, keys -> nombre de elem. top, value-> elem. top
  private Hashtable elements;
  
  // fecha de creacion
  private Date creationDate;
  
  /** Creates a new instance of LDAPModel */
  public LDAPModel( Hashtable model )
  {
    this.elements = model;
    this.creationDate = new Date ();
  }
  
  public int compareTo(Object o)
  {
    LDAPModel another = (LDAPModel) o;
    // comparacion inversa, primero el + reciente
    return another.getCreationDate().compareTo ( this.creationDate );
  }
  
  /** Getter for property elements.
   * @return Value of property elements.
   *
   */
  public java.util.Hashtable getElements()
  {
    return elements;
  }  
  
  /** Getter for property creationDate.
   * @return Value of property creationDate.
   *
   */
  public java.util.Date getCreationDate()
  {
    return creationDate;
  }
  
  public String toString () 
  {
    //StringBuffer out = new StringBuffer( this.getClass().getName() );
    StringBuffer out = new StringBuffer( super.toString() );
    out.append( " [CreationDate:" ).append( this.creationDate.toString() ).append( "]" );
    
    return out.toString();
    
  }
  
}
