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
import javax.ejb.*;
import pkiva.exceptions.*;

public interface Signature   extends EJBObject 
{

  /** Gets the signature for a clear text using a pkcs12
   * @param pkcs12 PKCS12 where to obtain the certificates to sign.
   * @param certAlias Alias inside PKCS12 of the Certificate to use in signature.
   * @param storePwd Password for the pkcs12
   * @param clearText Text to sign.
   * @throws RemoteException ejb
   * @throws SignerException If signature fails for any reason.
   * @return The signature for given clear text.
   */
  //public byte[] getSignature(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText) throws  RemoteException, SignerException;

  /** Gets the signature for a clear text using a pkcs12
   * @param pkcs12 PKCS12 where to obtain the certificates to sign.
   * @param certAlias Alias inside PKCS12 of the Certificate to use in signature.
   * @param storePwd Password for the pkcs12
   * @param clearText Text to sign.
   * @param algorithm algorithm to use
   * @throws RemoteException ejb
   * @throws SignerException If signature fails for any reason.
   * @return The signature for given clear text.
   */
  //public byte[] getSignature(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText, String algorithm) throws  RemoteException, SignerException;

  /** Verifies signature of a given text with a pkcs7
   * @param pkcs7 pkcs containing certificates and signature
   * @param texto Clear text to verify.
   * @throws RemoteException ejb
   * @throws DigitalSignatureValidationErrorException In case of error.
   * @return true if signature validation succeedes, false otherwise.
   */
  public boolean verifySignature(byte[] pkcs7, byte[] texto) throws  RemoteException, DigitalSignatureValidationErrorException;

  /** Verifies signature of a given text with a pkcs7
   * @param pkcs7 pkcs containing certificates and signature
   * @throws RemoteException ejb
   * @throws DigitalSignatureValidationErrorException In case of error.
   * @return true if signature validation succeedes, false otherwise.
   */
  public boolean verifySignature(byte[] pkcs7) throws  RemoteException, DigitalSignatureValidationErrorException;

  /** Verifies signature of a given text with a pkcs7
  * @param pkcs7 pkcs containing certificates and signature
  * @param texto Text digest to verify.
  * @throws RemoteException ejb
  * @throws DigitalSignatureValidationErrorException In case of error.
  * @return true if signature validation succeedes, false otherwise.
  */
  public boolean verifyDigest(byte[] pkcs7, byte[] texto) throws  RemoteException, DigitalSignatureValidationErrorException;
}
