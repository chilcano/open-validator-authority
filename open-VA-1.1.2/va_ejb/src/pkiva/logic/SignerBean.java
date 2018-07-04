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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.*;
import java.io.ByteArrayInputStream;
import org.bouncycastle.jce.PKCS7SignedData;
import java.rmi.*;
import javax.ejb.*;
import pkiva.exceptions.*;
import pkiva.services.ServiceLocator;

public class SignerBean   implements SessionBean {
    private SessionContext context;
    
    public  byte[] sign(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText) throws
    RemoteException, SignerException{
        pkiva.log.LogManager.getLogger(this.getClass()).debug("SignerBean.sign(). Parameters: pkcs12=" + pkcs12 + ", certAlias=" + certAlias+ ", storePwd=" + storePwd+ ", clearText=" + clearText);
        return  sign(pkcs12,certAlias,storePwd,clearText,"SHA1");
        
    }
    public  byte[] sign(byte[] pkcs12, String certAlias,String storePwd, byte[] clearText, String algorithm) throws
    RemoteException, SignerException{
        pkiva.log.LogManager.getLogger(this.getClass()).debug("SignerBean.sign(). Parameters: pkcs12=" + pkcs12 + ", certAlias=" + certAlias+ ", storePwd=" + storePwd+ ", clearText=" + clearText+ ", algorithm=" + algorithm);
        try{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());            
            KeyStore keystore = KeyStore.getInstance("PKCS12","BC");
            keystore.load(new ByteArrayInputStream(pkcs12), storePwd.toCharArray());
            java.security.cert.Certificate[] certs=keystore.getCertificateChain(certAlias);            
            PrivateKey privKey=(PrivateKey)keystore.getKey(certAlias,storePwd.toCharArray());  
            PKCS7SignedData pkcs7 = new PKCS7SignedData(privKey, certs, algorithm );
            pkcs7.update(clearText, 0, clearText.length);
            //pkcs7.sign();
            return pkcs7.getEncoded();
        }
        catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).info("Exception signing byte[]: ",e);
            throw new SignerException(e.getMessage());
        }
    }
    
    public SignerBean() {}    
    public void ejbCreate() throws CreateException {}    
    public void setSessionContext(SessionContext theContext) {this.context = theContext;}    
    public void ejbActivate() {}    
    public void ejbPassivate() {}    
    public void ejbRemove() {}
}
