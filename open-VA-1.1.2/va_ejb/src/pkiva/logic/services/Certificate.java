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
package pkiva.logic.services;

import java.security.cert.*;
import java.rmi.*;
import java.util.*;
import javax.ejb.*;
import org.bouncycastle.asn1.*;
import pkiva.exceptions.DigitalSignatureValidationErrorException;
import pkiva.validation.CertValidationRequest;
import pkiva.validation.CertValidationResponse;

public interface Certificate   extends EJBObject 
{

    /** Gets a field from a certificate
     * @param certificate Certificate to get info from.
     * @param dataItem String representing the certificate path.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return The object retrieved from certificate, or null if nothing appropiate is found.
     */
    public Object getData(byte[] cert, String dataItem) throws RemoteException,CertificateException;

    /** Gets a field from a certificate
     * @param certificate Certificate to get info from.
     * @param dataItem String representing the certificate path.
     * @throws RemoteException ejb
     * @throws CertificateException If certificate error occurs.
     * @return The object retrieved from certificate, or null if nothing appropiate is found.
     * @see pkiva.parsing.Certificate
     */
    public Object getData(X509Certificate cert, String dataItem) throws RemoteException,CertificateException;

    //public Object getData(DERObject cert, String dataItem) throws RemoteException,CertificateException;
    
    /*
    public boolean isValid(X509Certificate certificate) throws RemoteException,CertificateException;
    public boolean isValid(X509Certificate[] certChain) throws RemoteException,CertificateException;
    public boolean isValid(byte[] pkcs7) throws RemoteException,CertificateException;
    public boolean isValid(X509Certificate certificate, Set policies) throws RemoteException,CertificateException;
    public boolean isValid(X509Certificate[] certChain, Set policies) throws RemoteException,CertificateException;
    public boolean isValid(byte[] pkcs7, Set policies) throws RemoteException,CertificateException;
    */

    /** Checks certificate validity.
     * @param request Certificate validation request information (certificate and parameters)
     * @throws RemoteException ejb
     * @return CertValidationResponse object with validation information 
     */
    public CertValidationResponse isValid(CertValidationRequest request) throws RemoteException;

    /*
    public boolean isCAAccepted(X509Certificate certificate, String profileId) throws RemoteException,CertificateException;
    public void setCAAccepted(X509Certificate certificate, String profileId,boolean accepted) throws RemoteException,CertificateException;
    */
}
