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
/** This class represents a Certificate as a Tree of objects, that can be retrieved
 * through JXPath.
 * @author caller
 */
public class CertificateTree {
    /** Used to resolve object positional queries */    
    protected CertificateAccessor ca=null;
    /** Object representing the TBSCertificate */    
    protected TBSCertificate tbsCertificate=null;
    /** Object representing the algorithmIdentifier */    
    protected AlgorithmIdentifier algorithmIdentifier=null;
    /** byte[] representing the certificate signature */    
    protected byte[] signatureValue=null;
    /** Creates a new instance of CertificateTree
     * @param ca Used to resolve object positional queries
     */
    public CertificateTree(CertificateAccessor ca){
        this.ca=ca;
        tbsCertificate=new TBSCertificate(ca);
        algorithmIdentifier=new AlgorithmIdentifier((ASN1SequenceWrapper)ca.getValue("/objects[2]"));
        signatureValue = ca.getSignature();
    }
    
    /**
     * @return Object representing the TBSCertificate
     */    
    public TBSCertificate getTbsCertificate(){
        return tbsCertificate;
    }
    
    /**
     * @return Object representing the algorithmIdentifier
     */    
    public AlgorithmIdentifier getSignatureAlgorithm(){
        return algorithmIdentifier;
    }
    
    /**
     * @return byte[] representing the certificate signature
     */    
    public byte[] getSignatureValue(){
        return signatureValue;
    }
    
    /**
     * @return A String representation for this object.
     */    
    public String toString(){
        return 
        getTbsCertificate()+"\n"
        +getSignatureAlgorithm()+"\n"
        +"<signature>"+DERObjectWrapper.toHexaReadable(getSignatureValue())+"</signature>";
    }
}
