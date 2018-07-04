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
package pkiva.validation.crl;
/**
 * Class: IssuingDistributionPoint
 *
 */

import javax.naming.*;
import javax.naming.directory.*;

public class IssuingDistributionPoint
{
  // tipos de CRLDP
  public final static String UNKNOWN_DPTYPE = "UNKNOWN_DPTYPE"; // dp built from Certificate
  public final static String URI_DPTYPE = "URI";
  public final static String INCOMPLETE_DPTYPE = "DN_INCOMPLETE";
  public final static String DEFAULT_DPTYPE = URI_DPTYPE;

  protected String location;
  protected String dpType;
  protected Attributes atts;
  
  /**
   * IssuingDistributionPoint class constructor
   * @param
   */
  public IssuingDistributionPoint( String uri )
  {
    this ( uri, UNKNOWN_DPTYPE );
  }
  
  /**
   * IssuingDistributionPoint class constructor
   * @param
   */
  public IssuingDistributionPoint( String uri, String type )
  {
    this.location = uri;
    this.dpType = type;
    this.atts = new BasicAttributes();
  }
  
  public String getLocation( )
  {
    return this.location;
  }
  
  public String getDPType( )
  {
    return this.dpType;
  }
  
  public boolean equals( Object obj )
  {
    boolean eq = super.equals( obj );
    
    // if references are not equal, let's find out about locations and types
    if ( ! eq )
      if ( obj instanceof IssuingDistributionPoint )
      {
        IssuingDistributionPoint idp = (IssuingDistributionPoint) obj;
		eq = this.location.equalsIgnoreCase( idp.getLocation() ) && 
            ( this.dpType.equals( UNKNOWN_DPTYPE ) || ( idp.getDPType( ).equals( UNKNOWN_DPTYPE ) ) || this.dpType.equalsIgnoreCase( idp.getDPType() ) );

      }
    
    return eq;
  }

		// diriarte: 20051114
  public int hashCode()
	{	
		if ( this.location != null )
		{
			return location.hashCode();
		} else
		{
			return super.hashCode();
		}
	}
	 
	
  
  public String toString()
  {
    StringBuffer out = new StringBuffer( this.getClass().getName() );
    out.append( " [" ).append( this.dpType ).append( ":" ).append( this.location )
      .append ( ".Attributes:" ).append ( atts ).append( "]" );
    
    return out.toString();
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
