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
import java.math.BigInteger;
/** Abstract class that is extended to wrap all the DERObject subclasses
 * @author caller
 */
public abstract class DERObjectWrapper {
    /** DERObject wrapped */    
    DERObject obj;
    
    /** Constructs a new wrapper around given DERObject
     * @param o DERObject to wrap
     */
    public DERObjectWrapper(DERObject o){
        obj=o;
    }

    /** Constructs a new wrapper around given DERObject
     * @param o DERObject to wrap
     * @return A DERObjectWrapper subclass suitable for given object.
     */    
    public static DERObjectWrapper getDERObjectWrapper(DERObject o){
        if(o instanceof ASN1Null){
            return new ASN1NullWrapper(o);
        }
        else if(o instanceof ASN1OctetString){
            return new ASN1OctectStringWrapper(o);
        }
        else if(o instanceof ASN1Sequence){
            return new ASN1SequenceWrapper(o);
        }
        else if(o instanceof ASN1Set){
            return new ASN1SetWrapper(o);
        }
        else if(o instanceof ASN1TaggedObject){
            return new ASN1TaggedObjectWrapper(o);
        }
        else if(o instanceof DERApplicationSpecific){
            return new DERApplicationSpecificWrapper(o);
        }
        else if(o instanceof DERBitString){
            return new DERBitStringWrapper(o);
        }
        else if(o instanceof DERBMPString){
            return new DERBMPStringWrapper(o);
        }
        else if(o instanceof DERBoolean){
            return new DERBooleanWrapper(o);
        }
        else if(o instanceof DEREnumerated){
            return new DEREnumeratedWrapper(o);
        }
        else if(o instanceof DERGeneralizedTime){
            return new ASN1NullWrapper(o);
        }
        else if(o instanceof DERIA5String){
            return new DERIA5StringWrapper(o);
        }
        else if(o instanceof DERInteger){
            return new DERIntegerWrapper(o);
        }
        else if(o instanceof DERNumericString){
            return new DERNumericStringWrapper(o);
        }
        else if(o instanceof DERObjectIdentifier){
            return new DERObjectIdentifierWrapper(o);
        }
        else if(o instanceof DERPrintableString){
            return new DERPrintableStringWrapper(o);
        }
        else if(o instanceof DERT61String){
            return new DERT61StringWrapper(o);
        }
        else if(o instanceof DERUniversalString){
            return new DERUniversalStringWrapper(o);
        }
        else if(o instanceof DERUnknownTag){
            return new DERUnknownTagWrapper(o);
        }
        else if(o instanceof DERUTCTime){
            return new DERUTCTimeWrapper(o);
        }
        else if(o instanceof DERUTF8String){
            return new DERUTF8StringWrapper(o);
        }
        else if(o instanceof DERVisibleString){
            return new DERVisibleStringWrapper(o);
        }
        return null;
    }
    
    /** Returns a value that best represents this object. Object returned is a standard
     * java class: String, Date, Boolean, ...
     * @param d DERObject to obtain value from. If it is null, current object is used.
     * @return The value that best represents this object. Object returned is a standard
     * java class: String, Date, Boolean, ...
     */
    public abstract Object getRepresentativeValue(DERObjectWrapper d);

    /** Converts a BigInteger to a hexa String like "AB 1F EC 09 0E"
     * @param i BigInteger to convert
     * @return A hexa String like "AB 1F EC 09 0E"
     */
    public static String toHexaString(BigInteger i){
        return toHexaString(i.toByteArray());
    }
    
    /** Converts a byte[] to a hexa String like "AB 1F EC 09 0E"
     * @param b byte[] to convert
     * @return A hexa String like "AB 1F EC 09 0E"
     */
    public static String toHexaString(byte[] b){
        StringBuffer sb = new StringBuffer();
        for(int i=0;i<b.length;i++){
            if(i!=0)
                sb.append(" ");
            sb.append(toHexaString(b[i]));
        }
        return sb.toString();
    }
    
    private static String hexas="0123456789ABCDEF";
    
    /** Converts a byte to a hexa String like "A1"
     * @param b byte to convert
     * @return A hexa String like "A1"
     */
    public static String toHexaString(byte b){
        byte b0 = (byte)((b>>4)&0x0F);
        byte b1 = (byte)(b&0x0F);
        return ""+hexas.charAt((int)b0)+hexas.charAt((int)b1);
    }
    
    /** Generates a readable byte[] description
     * @param b byte[] to convert
     * @return A readable byte[] description
     */
    public static String toHexaReadable(byte[]b){
        StringBuffer sb = new StringBuffer();
        if (b==null)
            sb.append("[0 bytes]");
        else{
            sb.append("[");
            sb.append(b.length);
            sb.append(" bytes]=");
            sb.append(toHexaString(b));
        }
        return sb.toString();
    }
    
    /** Generates a readable byte[] description
     * @param i BigInteger to convert
     * @return A readable byte[] description
     */
    public static String toHexaReadable(BigInteger i){
        return toHexaReadable(i.toByteArray());
    }
}
