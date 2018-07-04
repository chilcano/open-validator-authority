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
package pkiva.parsing;

import pkiva.parsing.wrappers.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import java.io.*;
import java.util.*;
import org.apache.commons.jxpath.*;
import java.math.BigInteger;
import java.security.cert.*;
/** Allows access to a certificate using JXPath based on object positions. It
 * provides also shortcuts to tipical values inside certificates, and some tools.
 * This class is intended to be used only by Certificate, thats why constructors
 * are package protected.
 * @author caller
 */
public class CertificateAccessor {
    
    /** Path to version */
    public static final String VERSION          = "/objects[1]/objects[1]";
    /** Path to Serial Number */
    public static final String SERIAL_NUMBER    = "/objects[1]/objects[2]";
    /** Path to Signature Algorithm */
    public static final String SIG_ALGORITHM    = "/objects[1]/objects[3]/objects[1]";
    /** Path to issuer */
    public static final String ISSUER           = "/objects[1]/objects[4]/objects/objects";
    /** Path to valid from */
    public static final String VALID_FROM       = "/objects[1]/objects[5]/objects[1]";
    /** Path to valid to */
    public static final String VALID_TO         = "/objects[1]/objects[5]/objects[2]";
    /** Path to subject */
    public static final String SUBJECT          = "/objects[1]/objects[6]/objects/objects";
    /** Path to pk algorithm */
    public static final String PK_ALGORITHM     = "/objects[1]/objects[7]/objects[1]/objects[1]";
    /** Path to pk key */
    public static final String PK_KEY           = "/objects[1]/objects[7]/objects[2]";
    /** Path to extensions */
    public static final String EXTENSIONS       = "//objects[tagNo=3]/object/objects";
    /** Path to optional field issuerUniqueID*/
    public static final String ISSUER_UID       = "//objects[tagNo=1]";
    /** Path to optional field subjectUniqueID*/
    public static final String SUBJECT_UID       = "//objects[tagNo=2]";
    /** Path to algorithm identifier */
    public static final String ID_ALGORITHM     = "/objects[2]/objects[1]";
    /** Path to signature */
    public static final String SIGNATURE        = "/objects[3]";
    
    /** Certificate used as a wrapping object */
    DERObjectWrapper certificate = null;
    /** Certificate used as a DERobject */
    DERObject certificateDERObject = null;
    /** JXPath context created on the certificate. */
    JXPathContext context = null;
    
    /** Creates a new instance of CertificateAccesor.
     * @param cert The cetificate to process as a byte[].
     * @throws IOException If error occurs accessing the stream.
     */
    CertificateAccessor(byte[] cert) throws IOException{
        this(new ByteArrayInputStream(cert));
    }
    
    /** Creates a new instance of CertificateAccesor.
     * @param cert The cetificate to process.
     * @throws IOException If error occurs accessing the stream.
     * @throws CertificateEncodingException If an encoding error occurs.
     */
    CertificateAccessor(X509Certificate cert) throws IOException,CertificateEncodingException{
        this(new ByteArrayInputStream(cert.getEncoded()));
    }
    
    /** Creates a new instance of CertificateAccesor.
     * @param is InputStream where to read the certificate.
     * @throws IOException If error occurs accessing the stream.
     */
    CertificateAccessor(InputStream is) throws IOException{
        ASN1InputStream asn1is = new ASN1InputStream(is);
        certificateDERObject = (DERObject)asn1is.readObject();
        certificate = DERObjectWrapper.getDERObjectWrapper(certificateDERObject);
        context = JXPathContext.newContext(certificate);
        asn1is.close();
    }
    
    /** Creates a new instance of CertificateAccesor
     * @param cert Certificate to use
     * @throws IOException If error occurs accessing the stream.
     */
    CertificateAccessor(DERObject cert) throws IOException{
        certificateDERObject=cert;
        certificate = DERObjectWrapper.getDERObjectWrapper(cert);
        context = JXPathContext.newContext(certificate);
    }
    
    public X509Certificate getX509Certificate() throws IOException,CertificateException{
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ASN1OutputStream aos = new ASN1OutputStream(bos);
        aos.writeObject(certificateDERObject);
        aos.flush();
        ByteArrayInputStream bis = new ByteArrayInputStream( bos.toByteArray() );
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(bis);
        bis.close();
        aos.close();
        if(cert==null){
            pkiva.log.LogManager.getLogger(this.getClass()).warn("Generating NULL certificate from "+DERObjectWrapper.toHexaString(bos.toByteArray()));
        }
        return cert;
    }
    
    
    /** Resolves a path based on object positions.
     * @param s Path to resolve.
     * @return The object in that place, or null if it is not found, or is not
     * representable using a DERObject.
     */
    public DERObjectWrapper getValue(String s){
        try{
            return (DERObjectWrapper)context.getValue(s);
        }
        catch (Throwable t){
            return null;
        }
    }
    
    /** Resolves a path based on object positions.
     * @param s Path to resolve.
     * @return Iterator to the set of objects found.
     */
    public Iterator iterate(String s){
        return context.iterate(s);
    }
    
    /** Retrieves first object with given oid.
     * @param s OID to find
     * @return The first object found or null if nothing is found.
     */
    public Object getByOID(String s){
        return getValue("//objects[objects/id='"+s+"']/objects[2]").getRepresentativeValue(null);
    }
    
    /** Retrieves all objects with given oid.
     * @param s OID to find
     * @return an iterator to all objects matching given id
     */
    public Iterator getTreeByOID(String s){
        String sPath="//objects[starts-with(objects/id,'"+s+"')]/objects[2]";
        Iterator it = iterate(sPath);
        return it;
    }
    
    /** Version
     * @return Certificate version
     */
    public String getVersion(){
        Object value = getValue(VERSION).getRepresentativeValue(null);
        if(value instanceof BigInteger){
            return "V"+(((BigInteger)value).intValue()+1);
        }
        else
            return null;
    }
    
    /** Serial Number
     * @return Certificate Serial Number
     */
    public BigInteger getSerialNumber(){
        return (BigInteger)getValue(SERIAL_NUMBER).getRepresentativeValue(null);
    }
    
    /** Signature Algorithm
     * @return Certificate Signature Algorithm
     */
    public String getSignatureAlgorithmIdentifier(){
        return (String)(getValue(SIG_ALGORITHM).getRepresentativeValue(null));
    }
    
    /** Issuer
     * @return Certificate issuer
     */
    public Hashtable getIssuer(){
        Hashtable h = new Hashtable();
        for(Iterator it = iterate(ISSUER);it.hasNext();){
            ASN1SequenceWrapper a = (ASN1SequenceWrapper)it.next();
            Vector v = (Vector)a.getRepresentativeValue(null);
            h.put(
            ((DERObjectWrapper)v.elementAt(0)).getRepresentativeValue(null),
            ((DERObjectWrapper)v.elementAt(1)).getRepresentativeValue(null)
            );
        }
        return h;
    }
    
    /** Start date.
     * @return Certificate Start date.
     */
    public Date getValidFrom(){
        return (Date)(getValue(VALID_FROM)).getRepresentativeValue(null);
    }
    
    /** End date.
     * @return Certificate End date.
     */
    public Date getValidTo(){
        return (Date)(getValue(VALID_TO)).getRepresentativeValue(null);
    }
    
    /** Subject
     * @return Certificate Subject
     */
    public Hashtable getSubject(){
        Hashtable h = new Hashtable();
        for(Iterator it = iterate(SUBJECT);it.hasNext();){
            ASN1SequenceWrapper a = (ASN1SequenceWrapper)it.next();
            Vector v = (Vector)a.getRepresentativeValue(null);
            h.put(
            ((DERObjectWrapper)v.elementAt(0)).getRepresentativeValue(null),
            ((DERObjectWrapper)v.elementAt(1)).getRepresentativeValue(null)
            );
        }
        return h;
    }
    
    /** Public key algorithm.
     * @return Certificate Public key algorithm oid.
     */
    public String getPKAlgorithm(){
        return (String)(getValue(PK_ALGORITHM)).getRepresentativeValue(null);
    }
    
    /** Public key value
     * @return Public key value
     */
    public byte[] getPKValue(){
        return (byte[])(getValue(PK_KEY)).getRepresentativeValue(null);
    }
    
    /** Public key algorithm and value.
     * @return A hashtable with algorithm name mapping pk value.
     */
    public HashMap getPK(){
        HashMap h = new HashMap(1);
        h.put( getPKAlgorithm(),getPKValue() );
        return h;
    }
    
    /** Optional field IssuerUniqueID.
     * @return The content of field IssuerUniqueID, or null if it is not present.
     */
    public byte[] getIssuerUniqueID(){
        DERObjectWrapper obj=getValue(ISSUER_UID);
        if(obj==null)
            return null;
        return (byte[])obj.getRepresentativeValue(null);
    }
    
    /** Optional field SubjectUniqueID.
     * @return The content of field SubjectUniqueID, or null if it is not present.
     */
    public byte[] getSubjectUniqueID(){
        DERObjectWrapper obj=getValue(ISSUER_UID);
        if(obj==null)
            return null;
        return (byte[])obj.getRepresentativeValue(null);
    }
    
    /** Extensions
     * @return Extensions
     */
    public Hashtable getExtensions(){
        Hashtable h = new Hashtable();
        for(Iterator it = iterate(EXTENSIONS);it.hasNext();){
            Object o = it.next();
            if (o instanceof ASN1SequenceWrapper){
                Vector v = (Vector)((ASN1SequenceWrapper)o).getRepresentativeValue(null);
                if(v.size()==2)
                    h.put(
                    ((DERObjectWrapper)v.elementAt(0)).getRepresentativeValue(null),
                    ((DERObjectWrapper)v.elementAt(1)).getRepresentativeValue(null)
                    );
                else if (v.size()==3){
                    Vector vExt = new Vector(2);
                    vExt.add(((DERObjectWrapper)v.elementAt(1)).getRepresentativeValue(null));
                    vExt.add(((DERObjectWrapper)v.elementAt(2)).getRepresentativeValue(null));
                    h.put(
                    ((DERObjectWrapper)v.elementAt(0)).getRepresentativeValue(null),
                    vExt
                    );
                }
            }
        }
        return h;
    }
    
    /** Signature algorithm
     * @return Signature algorithm
     */
    public String getSignatureAlgorithm(){
        return (String)(getValue(ID_ALGORITHM)).getRepresentativeValue(null);
    }
    
    /** Signature bits
     * @return Signature bits
     */
    public byte[] getSignature(){
        return (byte[])(getValue(SIGNATURE)).getRepresentativeValue(null);
    }
    
    /** Return a String representation for this object
     * @return A String representation for this object
     */
    public String toString(){
        StringBuffer sb = new StringBuffer();
        sb.append("Version: "+getVersion()+"\n");
        sb.append("Número de serie: "+DERObjectWrapper.toHexaString(getSerialNumber())+"\n");
        sb.append("Algoritmo de firma: "+getSignatureAlgorithmIdentifier()+"\n");
        sb.append("Emisor: "+getIssuer()+" \n");
        sb.append("Desde: "+getValidFrom()+" \n");
        sb.append("Hasta: "+getValidTo()+" \n");
        sb.append("Asunto: "+getSubject()+"\n");
        sb.append("Clave Pública: ("+getPKAlgorithm()+") = ["+getPKValue().length+" bytes]="+DERObjectWrapper.toHexaString(getPKValue())+" \n");
        Hashtable extensions = getExtensions();
        //sb.append("Extensiones: "+getExtensions()+"\n");
        for(Enumeration e = extensions.keys();e.hasMoreElements();){
            Object key=e.nextElement();
            byte[] val=(byte[])extensions.get(key);
            //sb.append("Extension: "+key+" -> ["+val.length+" bytes]="+toHexaString(val)+"\n");
            sb.append("Extension: "+key+" -> ["+val.length+" bytes]="+new String(val)+"\n");
        }
        sb.append("Algoritmo de firma(2): "+getSignatureAlgorithm()+"\n");
        sb.append("Firma: ["+getSignature().length+" bytes]="+DERObjectWrapper.toHexaString(getSignature())+"\n");
        return sb.toString();
    }
}
