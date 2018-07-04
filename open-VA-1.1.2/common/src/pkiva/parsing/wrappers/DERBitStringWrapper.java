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
 * Wraps a DERBitString
 * @author  caller
 */
public class DERBitStringWrapper extends DERObjectWrapper {
    
    /** Creates a new instance of DERBitStringWrapper 
     * @param o Object to wrap
     */
    public DERBitStringWrapper(DERObject o) {
        super(o);
    }
    
    /**
     * Returns the value represented by this object
     * @return the value represented by this object
     */
    public byte[] getBytes(){
        return ((DERBitString)obj).getBytes();
    }
            
    /**
     * Returns the padding bits in this object
     * @return the padding bits in this object
     */
    public int getPadBits(){
        return ((DERBitString)obj).getPadBits();
    }

    /** Returns a value that best represents this object. Object returned is a standard
     * java class: String, Date, Boolean, ...
     * @param d DERObject to obtain value from. If it is null, current object is used.
     * @return The value that best represents this object. Object returned is a byte[].
     */    
    public Object getRepresentativeValue(DERObjectWrapper d) {
        if(d!=null) return d.getRepresentativeValue(null);
        return getBytes();
    }
    
    /** String representation for this object.
     * @return A String representation for this object.
     */
     public String toString(){
        return toHexaReadable(getBytes());
     }    
}
