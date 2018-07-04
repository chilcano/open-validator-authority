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
 * Wraps a DERObjectIdentifier
 * @author  caller
 */
public class DERObjectIdentifierWrapper extends DERObjectWrapper {
    
    /** Creates a new instance of DEREnumeratedWrapper 
     * @param 0 Object to wrap
     */
    public DERObjectIdentifierWrapper(DERObject o) {
        super(o);
    }

    /**
     * Returns the id represented by this object
     * @return the id represented by this object
     */
    public String getId(){
        return ((DERObjectIdentifier)obj).getId();
    }
    
    /** String representation for this object.
     * @return A String representation for this object.
     */
    public String toString(){
        return "OID:"+getId();
    }
    
    /** Returns a value that best represents this object. Object returned is a standard
     * java class: String, Date, Boolean, ...
     * @param d DERObject to obtain value from. If it is null, current object is used.
     * @return The value that best represents this object. Object returned is a String
     */    
    public Object getRepresentativeValue(DERObjectWrapper d) {
        if(d!=null) return d.getRepresentativeValue(null);
        return getId();
    }
    
}
