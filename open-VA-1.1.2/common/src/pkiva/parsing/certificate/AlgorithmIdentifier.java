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
import java.util.*;
/** This class represents an Algorithm identifier. It contains fields for algorithm
 * oid and parameters.
 * @author caller
 */
public class AlgorithmIdentifier {

    /** Sequence where to obtain values */
    ASN1SequenceWrapper a=null;
    /** Algorithm oid */
    String algorithm=null;
    /** Parameters */
    Object parameters=null;
    /** Creates a new instance of AlgorithmIdentifier
     * @param a Sequence where to obtain values
     */
    public AlgorithmIdentifier(ASN1SequenceWrapper a){
        this.a=a;
        algorithm=(String)((DERObjectIdentifierWrapper)((Vector)a.getRepresentativeValue(null)).elementAt(0)).getRepresentativeValue(null);
        parameters=((Vector)a.getRepresentativeValue(null)).elementAt(1);
    }

    /**
     * @return Algorithm oid
     */
    public String getAlgorithm(){
        return algorithm;
    }

    /**
     * @return Parameters
     */
    public Object getParameters(){
        return parameters;
    }

    /**
     * @return a String representation for this object.
     */
    public String toString(){
        return "<algorithm>"+algorithm+"("+parameters+")</algorithm>";
    }
}
