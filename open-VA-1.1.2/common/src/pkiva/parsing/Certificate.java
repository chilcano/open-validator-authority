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
import pkiva.parsing.certificate.*;
import java.security.cert.*;

/** This class represents a Certificate and allows access to it through JXPath,
 * either by field names or by object positions.
 * Sample usage can be found in main method:
 * <code>
 * Certificate c = new Certificate(new FileInputStream("c:\\antonio.cer"));
 * System.out.println(c);
 * System.out.println(c.getValue("/tbsCertificate"));
 * System.out.println(c.getValue("/signatureAlgorithm"));
 * System.out.println(c.getValue("/signatureValue"));
 * System.out.println(c.getValue("/tbsCertificate/version"));
 * System.out.println(c.getValue("/tbsCertificate/serialNumber"));
 * System.out.println(c.getValue("/tbsCertificate/signature"));
 * System.out.println(c.getValue("/tbsCertificate/issuer"));
 * System.out.println(c.getValue("/tbsCertificate/issuer[@name='2.5.4.10']"));
 * System.out.println(c.getValue("/tbsCertificate/issuer[@name='2.5.4.3']"));
 * System.out.println(c.getValue("/tbsCertificate/validity"));
 * System.out.println(c.getValue("/tbsCertificate/validity/notBefore"));
 * System.out.println(c.getValue("/tbsCertificate/validity/notAfter"));
 * System.out.println(c.getValue("/tbsCertificate/validity[@name='notBefore']"));
 * System.out.println(c.getValue("/tbsCertificate/validity[@name='notAfter']"));
 * System.out.println(c.getValue("/tbsCertificate/subject"));
 * System.out.println(c.getValue("/tbsCertificate/subject[@name='2.5.4.10']"));
 * System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo"));
 * System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm"));
 * System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm/algorithm"));
 * System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm/parameters"));
 * System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/subjectPublicKey"));
 * System.out.println(c.getValue("/tbsCertificate/extensions"));
 * System.out.println(c.getValue("/tbsCertificate/extensions[@extnID='2.16.840.1.113730.1.1']/critical"));
 * System.out.println(c.getValue("/tbsCertificate/extensions[@extnID='2.16.840.1.113730.1.1']/extnValue"));
 *
 * //by positions
 * System.out.println(c.getValue("/objects[1]/objects[1]"));
 * System.out.println(c.getValue("/objects[1]/objects[5]/objects[2]"));
 *
 * </code>
 * @author caller
 */
public class Certificate {
    /** Accessor used to resolve positional JXPath queries */
    CertificateAccessor ca = null;
    /** Tree used to create JXPath context based on names */
    CertificateTree ct=null;
    /** Context based on names */
    JXPathContext context = null;    
    
    /** Creates a new instance of Certificate.
     * @param cert The cetificate to process.
     * @throws IOException If error occurs accessing the stream.
     * @throws CertificateEncodingException If an encoding error occurs.
     */
    public Certificate(X509Certificate cert) throws IOException,CertificateEncodingException{
        ca = new CertificateAccessor(cert);
        ct = new CertificateTree(ca);
        context = JXPathContext.newContext(ct);
    }
    
    /** Creates a new instance of Certificate
     * @param is InputStream where to read the certificate as a DER encoded object
     * @throws IOException If error occurs accessing the stream
     */
    public Certificate(InputStream is) throws IOException{
        ca = new CertificateAccessor(is);
        ct = new CertificateTree(ca);
        context = JXPathContext.newContext(ct);
    }

    /** Creates a new instance of Certificate
     * @param b byte[] where to read the certificate as a DER encoded object
     * @throws IOException If error occurs
     */
    public Certificate(byte[] b) throws IOException{
        ca = new CertificateAccessor(b);
        ct = new CertificateTree(ca);
        context = JXPathContext.newContext(ct);
    }
    
    /** Creates a new instance of CertificateAccesor
     * @param cert Certificate object to use.
     * @throws IOException If error occurs accessing the stream
     */
    public Certificate(DERObject cert) throws IOException{
        ca = new CertificateAccessor(cert);
        ct = new CertificateTree(ca);
        context = JXPathContext.newContext(ct);
    }
    
    /** Resolves a path and returns the object found. The path can be either based on
     * names or positions (see class description for details)
     * @param s Path to resolve
     * @return The object found, or null in case it is not found. If path is a final node, it
     * will be a standard java object, otherwise it may be something inside
     * pkiva.parsing.certificate package, or a Hashtable or Vector.
     */
    public Object getValue(String s){
        try{
            return context.getValue(s);
        }
        catch(Exception e){
            try{
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Using positional query for path "+s);
                return ca.getValue(s).getRepresentativeValue(null);
            }
            catch(Exception e2){
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Failed to resolve path "+s);
                return null;
            }
        }
    }
    
    /** Resolves a path and iterates through the objects found. The path can be either based on
     * names or positions (see class description for details)
     * @param s Path to resolve
     * @return An iterator to the object(s) found. If path is a final node, element in
     * iterator will be a standard java object, otherwise it may be something inside
     * pkiva.parsing.certificate package, or a Hashtable or Vector.
     */
    public Iterator iterate(String s){
        try{
            return context.iterate(s);
        }
        catch(Exception e){
            try{
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Using positional query for path "+s);
                return ca.iterate(s);
            }
            catch(Exception e2){
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Failed to resolve path "+s);
                return null;
            }
        }
    }
    
    public X509Certificate getX509Certificate(){
        try{
            return ca.getX509Certificate();
        }
        catch( IOException ioe){
            pkiva.log.LogManager.getLogger(this.getClass()).error("Exception generating certificate: ",ioe);
            return null;
        }
        catch(CertificateException ce){
            pkiva.log.LogManager.getLogger(this.getClass()).error("Exception generating certificate: ",ce);
            return null;
        }
    }
    
    
    
    /** Return a String representation for this object.
     * @return A String representation for this object.
     */
    public String toString(){
        return ct.toString();
    }
    
    /** Sample usage
     * @param args ignored
     * @throws Exception in case of error
     */
    public static void main(String[] args) throws Exception {
        if(args.length!=1){
            System.out.println("Need a filename to process.");
            return;
        }
        
        InputStream inStream = new FileInputStream(args[0]);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        
        Certificate c = new Certificate(cert);
        System.out.println(c);
        System.out.println(c.getValue("/tbsCertificate"));
        System.out.println(c.getValue("/signatureAlgorithm"));
        System.out.println(c.getValue("/signatureValue"));
        System.out.println(c.getValue("/tbsCertificate/version"));
        System.out.println(c.getValue("/tbsCertificate/serialNumber"));
        System.out.println(c.getValue("/tbsCertificate/signature"));
        System.out.println(c.getValue("/tbsCertificate/issuer"));
        System.out.println(c.getValue("/tbsCertificate/issuer[@name='2.5.4.10']"));
        System.out.println(c.getValue("/tbsCertificate/issuer[@name='2.5.4.3']"));
        System.out.println(c.getValue("/tbsCertificate/validity"));
        System.out.println(c.getValue("/tbsCertificate/validity/notBefore"));
        System.out.println(c.getValue("/tbsCertificate/validity/notAfter"));
        System.out.println(c.getValue("/tbsCertificate/validity[@name='notBefore']"));
        System.out.println(c.getValue("/tbsCertificate/validity[@name='notAfter']"));
        System.out.println(c.getValue("/tbsCertificate/subject"));
        System.out.println(c.getValue("/tbsCertificate/subject[@name='2.5.4.10']"));
        System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo"));
        System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm"));
        System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm/algorithm"));
        System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/algorithm/parameters"));
        System.out.println(c.getValue("/tbsCertificate/subjectPublicKeyInfo/subjectPublicKey"));
        System.out.println(c.getValue("/tbsCertificate/extensions"));
        System.out.println(c.getValue("/tbsCertificate/extensions[@extnID='2.16.840.1.113730.1.1']/critical"));
        System.out.println(c.getValue("/tbsCertificate/extensions[@extnID='2.16.840.1.113730.1.1']/extnValue"));
        
        //by positions
        System.out.println(c.getValue("/objects[1]/objects[1]"));
        System.out.println(c.getValue("/objects[1]/objects[5]/objects[2]"));
        
    }
    
}
