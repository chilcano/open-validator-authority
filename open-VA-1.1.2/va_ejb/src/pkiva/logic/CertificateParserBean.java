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
package pkiva.logic;

import javax.ejb.*;
import java.net.*;
import java.io.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;
import java.rmi.*;
import pkiva.exceptions.*;
import pkiva.services.*;
import pkiva.log.*;
import pkiva.log.operations.*;
import java.security.cert.*;
import org.bouncycastle.asn1.*;

/** This class is the parser bean, that allows access to certificate properties 
 * using paths, like "/TBSCertificate/version"
 *
 * @author caller
 */
public class CertificateParserBean implements SessionBean {
    private SessionContext context;
    
    /**
     * @throws CreateException
     */    
    public void ejbCreate() throws CreateException  { }
    /**
     * @param theContext
     */    
    public void setSessionContext(SessionContext theContext) {
        this.context = theContext;
    }
    /** Gets the data associated to a given path inside a Certificate.
     * @param cert The certificate to process, in encoded form.
     * @param path The path to resolve inside certificate.
     * @throws RemoteException It is an ejb method...
     * @throws CertificateException If given certificate is invalid or unparseable.
     * @return The object indexed by given path, or null if nothing apropiate is found.
     */
    public Object getData(byte[] cert, String path) throws RemoteException,CertificateException{
        try{
            //return new pkiva.parsing.Certificate(cert).getValue(path);
            // Changes auditing Aug-04
            pkiva.parsing.Certificate parsingCert = new pkiva.parsing.Certificate(cert);
            Object obj = parsingCert.getValue(path);

            infoAndAudit ( CertUtils.getCertFromEncoded(cert), path, obj );

            return obj;
        }
        catch(AuditingException ae){
            throw new RemoteException("Internal Error getting Data from certificate", ae);
        }
        catch(IOException ioe){
            throw new CertificateException("Invalid encoded certificate.");
        }
    }

    /** Gets the data associated to a given path inside a Certificate.
     * @param cert The certificate to process.
     * @param path The path to resolve inside certificate.
     * @throws RemoteException It is an ejb method...
     * @throws CertificateException If given certificate is invalid or unparseable.
     * @return The object indexed by given path, or null if nothing apropiate is found.
     */    
    public Object getData(X509Certificate cert, String path) throws RemoteException,CertificateException{
        try{
            //return new pkiva.parsing.Certificate(cert).getValue(path);
            // Changes auditing Aug-04
            pkiva.parsing.Certificate parsingCert = new pkiva.parsing.Certificate(cert);
            Object obj = parsingCert.getValue(path);

            infoAndAudit ( cert, path, obj );

            return obj;
        }
        catch(AuditingException ae){
            throw new RemoteException("Internal Error getting Data from certificate", ae);
        }
        catch(CertificateEncodingException cee){
            throw new CertificateException("Invalid encoded certificate.");
        }
        catch(IOException ioe){
            throw new CertificateException("Invalid encoded certificate.");
        }
    }

  protected void infoAndAudit ( X509Certificate cert, String path, Object result ) throws AuditingException
  {
    String sn = CertUtils.getSerialNumberAsHexa (  cert );
    String ca = cert.getIssuerDN().getName();
    StringBuffer sb = new StringBuffer ( "Get field '" );
    sb.append ( path ).append ( "' from Certificate SN [" ).append (sn).
      append ("] CA [").append ( ca ).append ( "]:" ).append ( result );
    String msg = sb.toString();
    pkiva.log.LogManager.getLogger(this.getClass()).info(msg);

    // Changes auditing Aug-04
    //pkiva.log.AuditManager.getAuditer(this.getClass()).audit(msg);
    CertDataExtraction auditOperation = new CertDataExtraction();
    auditOperation.setCert(cert);
    auditOperation.setDataPath(path);
    auditOperation.setDataItem(result.toString());
    pkiva.log.AuditManager.getAuditer(this.getClass()).audit(auditOperation);

  }

    /** Gets the data associated to a given path inside a Certificate.
     * @param cert The certificate to process, in DERObject form.
     * @param path The path to resolve inside certificate.
     * @throws RemoteException It is an ejb method...
     * @throws CertificateException If given certificate is invalid or unparseable.
     * @return The object indexed by given path, or null if nothing apropiate is found.
     */    
    public Object getData(DERObject cert, String path) throws RemoteException,CertificateException{
        try{
            return new pkiva.parsing.Certificate(cert).getValue(path);
        }
        catch(IOException ioe){
            throw new CertificateException("Invalid encoded certificate.");
        }
    }
    
    public void ejbActivate()  { }
    public void ejbPassivate()  { }
    public void ejbRemove()   { }
}
