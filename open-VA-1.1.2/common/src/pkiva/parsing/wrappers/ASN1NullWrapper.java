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
package pkiva.parsing.wrappers;
import org.bouncycastle.asn1.*;

/**
 * Wraps a null
 * @author  caller
 */
public class ASN1NullWrapper extends DERObjectWrapper {
    
    /** Creates a new instance of DERASN1NullWrapper
     * @param o Object to wrap
     */
    public ASN1NullWrapper(DERObject o) {
        super(o);
    }
    
    /** String representation for this object.
     * @return A String representation for this object.
     */
    public String toString(){
        return "NULL";
    }
    
    /** Returns a value that best represents this object. Object returned is a standard
     * java class: String, Date, Boolean, ...
     * @param d DERObject to obtain value from. If it is null, current object is used.
     * @return null
     */    
    public Object getRepresentativeValue(DERObjectWrapper d) {
        return null;
    }    
}
