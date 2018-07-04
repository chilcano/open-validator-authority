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

/** Represent the first part of a certificate.
 * @author caller
 */
public class TBSCertificate {
    /** Used to resolve position-based queries. */    
    protected CertificateAccessor ca=null;
    /** Version field */    
    protected String version=null;
    /** Serial Number field */    
    protected BigInteger serialNumber=null;
    /** Signature algorithm identifier */    
    protected AlgorithmIdentifier signature=null;
    /** Issuer field */    
    protected Hashtable issuer=null;
    /** Validity field */    
    protected Hashtable validity=null;
    /** Subject field */    
    protected Hashtable subject=null;
    /** subjectPublicKeyInfo field */    
    protected Hashtable subjectPublicKeyInfo=null;
    /** Extensions field */    
    protected Vector extensions=null;
    /** Optional field IssuerUniqueID. */    
    protected byte[] issuerUniqueID=null;
    /** Optional field SubjectUniqueID. */    
    protected byte[] subjectUniqueID=null;
    
    /** Creates a new instance of TBSCertificate
     * @param ca Used to resolve position-based queries.
     */
    public TBSCertificate(CertificateAccessor ca) {
        this.ca = ca;
        version=ca.getVersion();
        serialNumber=ca.getSerialNumber();
        signature=new AlgorithmIdentifier((ASN1SequenceWrapper)ca.getValue("/objects[1]/objects[3]"));
        issuer=ca.getIssuer();
        validity = new Hashtable();
        validity.put("notBefore",ca.getValidFrom());
        validity.put("notAfter",ca.getValidTo());
        subject=ca.getSubject();
        subjectPublicKeyInfo=new Hashtable();
        subjectPublicKeyInfo.put("algorithm", new AlgorithmIdentifier((ASN1SequenceWrapper)ca.getValue("/objects[1]/objects[7]/objects[1]")));
        subjectPublicKeyInfo.put("subjectPublicKey",ca.getPKValue());
        issuerUniqueID=ca.getIssuerUniqueID();
        subjectUniqueID=ca.getSubjectUniqueID();
        extensions=new Vector();
        Hashtable hExt = ca.getExtensions();
        for(Enumeration e = hExt.keys();e.hasMoreElements();){
            String oid = (String)e.nextElement();
            Object val = hExt.get(oid);
            extensions.add(new Extension(oid,val));
        }
    }
    
    /** Version field
     * @return Version field
     */    
    public String getVersion(){
        return version;
    }
    
    /** Serial Number field
     * @return Serial Number field
     */    
    public BigInteger getSerialNumber(){
        return serialNumber;
    }
    
    /** Signature algorithm identifier
     * @return Signature algorithm identifier
     */    
    public AlgorithmIdentifier getSignature(){
        return signature;
    }
    
    /** Issuer field
     * @return Issuer field
     */    
    public Hashtable getIssuer(){
        return ca.getIssuer();
    }
    
    /** Validity field
     * @return Validity field
     */    
    public Hashtable getValidity(){
        return validity;
    }
    
    /** Subject field
     * @return Subject field
     */    
    public Hashtable getSubject(){
        return subject;
    }
    
    /** subjectPublicKeyInfo field
     * @return subjectPublicKeyInfo field
     */    
    public Hashtable getSubjectPublicKeyInfo(){
        return subjectPublicKeyInfo;
    }
    
    /** Optional field IssuerUniqueID.
     * @return The content of field IssuerUniqueID, or null if it is not present.
     */    
    public byte[] getIssuerUniqueID(){
        return issuerUniqueID;
    }
    
    /** Optional field SubjectUniqueID.
     * @return The content of field SubjectUniqueID, or null if it is not present.
     */    
    public byte[] getSubjectUniqueID(){
        return subjectUniqueID;
    }
    
    /** Extensions field
     * @return Extensions field
     */    
    public Vector getExtensions(){
        return extensions;
    }
    
    /** Return a String representation for this object
     * @return a String representation for this object
     */    
    public String toString(){
        StringBuffer sb = new StringBuffer();
        sb.append("<TBSCertificate>");
        sb.append("\nVersion:");
        sb.append(version);
        sb.append("\nSerialNumber:");
        sb.append(DERObjectWrapper.toHexaReadable(serialNumber));
        sb.append("\nSignature:");
        sb.append(signature);
        sb.append("\nIssuer:");
        sb.append(issuer);
        sb.append("\nValidity:");
        sb.append(validity);
        sb.append("\nSubject:");
        sb.append(subject);
        sb.append("\nSubjectPublicKeyInfo:");
        sb.append("{algorithm=");
        sb.append(subjectPublicKeyInfo.get("algorithm"));
        sb.append(", subjectPublicKey=");
        sb.append(DERObjectWrapper.toHexaReadable((byte[])subjectPublicKeyInfo.get("subjectPublicKey") ));
        sb.append("}");
        sb.append("\nIssuerUniqueID=");
        sb.append(DERObjectWrapper.toHexaReadable(issuerUniqueID));
        sb.append("\nSubjectUniqueID=");
        sb.append(DERObjectWrapper.toHexaReadable(subjectUniqueID));
        sb.append("\nExtensions:");
        sb.append(extensions);
        sb.append("\n</TBSCertificate>");
        return sb.toString();
    }
}
