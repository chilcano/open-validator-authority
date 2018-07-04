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
package pkiva.parsing.certificate;
import pkiva.parsing.*;
import pkiva.parsing.wrappers.*;
import java.math.BigInteger;
import java.util.*;
/** This class represents an extension in a certificate. It contains fields for the
 * id, the critical boolean and value.
 * @author caller
 */
public class Extension {
    /** Indicates if this extension is critical. */    
    protected boolean critical;
    /** Extension oid */    
    protected String extnID;
    /** The extension value */    
    protected byte[] extnValue;
    
    /** Creates a new instance of Extension
     * @param oid OID for this extension
     * @param val If extension has critical value (true or false) specified, it must be a Vector
     * with {Boolean,byte[]}. If critical is not specified (so it will be false), it
     * will be directly the byte[].
     */
    public Extension(String oid, Object val) {
        extnID = oid;
        if(val instanceof Vector){
            critical = ((Boolean)((Vector)val).elementAt(0)).booleanValue();
            extnValue = ((byte[])((Vector)val).elementAt(1));
        }
        else{
            critical = false;
            extnValue = (byte[]) val;
        }
    }
    
    /** Indicates if this extension is critical.
     * @return true if this extension is critical.
     */    
    public boolean getCritical(){
        return critical;
    }
    
    /** Extension oid
     * @return The extension oid
     */    
    public String getExtnID(){
        return extnID;
    }
    
    /** Return the extension value
     * @return The extension value
     */    
    public byte[] getExtnValue(){
        return extnValue;
    }
    
    /** Return a String representation for this object
     * @return a String representation for this object
     */    
    public String toString(){
        return "Extension:{ extnID="+extnID+", critical="+critical+", extnValue="+DERObjectWrapper.toHexaReadable(extnValue)+"}";
    }    
}
