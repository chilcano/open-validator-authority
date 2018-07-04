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
package pkiva.validation.ocsp;

import java.io.*;
import java.util.*;
import java.security.cert.*;
import java.security.*;
import org.bouncycastle.ocsp.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;

import pkiva.exceptions.*;
import pkiva.services.*;
import pkiva.providers.*;

/**
 *
 * @author  diriarte
 * Copied from [RFC2560]:
 * <pre>
 *    This specification defines the following definitive response
   indicators for use in the certificate status value:

   -- good
   -- revoked
   -- unknown

   The "good" state indicates a positive response to the status inquiry.
   At a minimum, this positive response indicates that the certificate
   is not revoked, but does not necessarily mean that the certificate
   was ever issued or that the time at which the response was produced
   is within the certificate's validity interval. Response extensions
   may be used to convey additional information on assertions made by
   the responder regarding the status of the certificate such as
   positive statement about issuance, validity, etc.

   The "revoked" state indicates that the certificate has been revoked
   (either permanantly or temporarily (on hold)).

   The "unknown" state indicates that the responder doesn't know about
   the certificate being requested.
 * </pre>
 */
public class OCSPClient
{
  
  // TODO: tratamiento de estados
  protected final int NOT_LOADED = 0;
  protected final int REQUEST_GENERATED = 1;
  /*protected final int = ;
  protected final int = ;*/
  
  protected X509Certificate[] chain;
  protected Hashtable certificatesRequested;
  protected int status;
  
  /** Creates a new instance of OCSPClient */
  public OCSPClient( X509Certificate[] chain )
  {
    this.chain = chain;
    this.status = NOT_LOADED;
  }
  
  public byte[] generateRequest( X509Certificate signcert, PrivateKey signkey, String signingAlgorithm, String provider ) throws OCSPException, IOException
  {
    boolean mustSign = ! ( ( signcert == null ) || (signkey == null ) );

    this.certificatesRequested = new Hashtable();
    OCSPReqGenerator gen= new OCSPReqGenerator();
    
    // introducir los certificados en la peticion
    CertificateID[] certIDs = getCertIDs( chain );
    for (int i=0; i < certIDs.length; ++i)
      gen.addRequest(certIDs[i]);
    
    byte[] ocspData = null;
    if (mustSign)
    {
      gen.setRequestorName(new GeneralName(new X509Name(signcert.getSubjectX500Principal().getName())));
      
      if ( ( signingAlgorithm != null ) && ( provider != null ) )
      {
        try
        {
          // signed request
          X509Certificate[] signChain = new X509Certificate[] {signcert};
          ocspData= gen.generate( signingAlgorithm, signkey, signChain, provider).getEncoded();
        }
        catch ( Exception e )
        {
          pkiva.log.LogManager.getLogger(this.getClass()).error("Error generating signed OCSP Request, we'll retry unsigned", e);
          ocspData = null;
        }
      }
      
    }

    if ( ocspData == null)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Generating unsigned OCSP Request ");
      // not signed request
      ocspData= gen.generate().getEncoded();
    }

    this.status = REQUEST_GENERATED;
    return ocspData;
  }
  
  public OCSPValidationInfo checkChainStatus( SingleResp[] responses, byte[] ocsprespdata, X509Certificate ocspCert ) throws java.security.cert.CertPathValidatorException
  {
    Date now = TimeProvider.getCurrentTime().getTime();
    
    Collection okCerts = new Vector();
    Collection unknownCerts = new Vector();
    Collection revokedCerts = new Vector();
    
    boolean anyRevoked = false;
    boolean anyUnknown = false;
    
    for (int i=0;i<responses.length;++i)
    {
      SingleResp sresp=responses[i];
      
      Date nextu=sresp.getNextUpdate();
      if (nextu!=null)
        if (now.after(nextu))
        {
          // TODO: OCSPServerException
          throw new OCSPValidationException("La respuesta del OCSP no esta actualizada");
        }
      
      X509Certificate cert=(X509Certificate)certificatesRequested.remove(sresp.getCertID());
      if (cert==null)
        throw new OCSPValidationException("Recibida respuesta con certificado no solicitado");
      
      CertificateStatus stat = (CertificateStatus) sresp.getCertStatus();
      if (stat == null)
      {
        okCerts.add( cert );
      }
      else if (stat instanceof UnknownStatus)
      {
        unknownCerts.add( cert );
        anyUnknown = true;
      }
      else if (stat instanceof RevokedStatus)
      {
        revokedCerts.add( cert );
        anyRevoked = true;
      }
      else
      {
        throw new OCSPValidationException("Respuesta sobre certificado con estado no reconocido:" + stat);
      }
    } // end for
    
    OCSPValidationInfo ocspInfo = new OCSPValidationInfo ( okCerts, revokedCerts, unknownCerts);
    ocspInfo.setOCSPCert( ocspCert );
    ocspInfo.setOCSPData( ocsprespdata );

    if ( anyRevoked )
    {
      CertificateChainRevocationException exc = new CertificateChainRevocationException("Revoked certificate via OCSP");
      exc.setValidationObject( ocspInfo );
      throw exc;
    }
    if ( anyUnknown )
    {
      UnknownCertificateChainRevocationStatusException exc = new UnknownCertificateChainRevocationStatusException("Any certificate status in unknown via OCSP");
      exc.setValidationObject( ocspInfo );
      throw exc;
    }
      
    return ocspInfo;    
  }
  
  // pre:( chain != null ) && ( chain.length >= 1 ) && chain is incomplete
  // chain no es forward (i.e. 1stCA is in position 0, final cert is in n, where n >= 1)
  protected CertificateID[] getCertIDs( X509Certificate[] chain ) throws OCSPException
  {
    CertificateID[] ids = new CertificateID[ chain.length ];
    
    X509Certificate trust = CertUtils.getTrustAnchor(CertStoreProvider.getTrustAnchors(), chain[0] );
    ids[ 0 ] = new CertificateID(CertificateID.HASH_SHA1, trust, chain[0].getSerialNumber() );
    this.certificatesRequested.put( ids[ 0 ], chain[0] );

    for ( int i = 1; i < chain.length; ++i)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Usamos para firmar CA:" + chain[i-1]);
      pkiva.log.LogManager.getLogger(this.getClass()).debug("firmamos certificado [s/n]:" + chain[i].getSerialNumber());
      ids[ i ] = new CertificateID(CertificateID.HASH_SHA1, chain[i-1], chain[i].getSerialNumber() );
      this.certificatesRequested.put( ids[i], chain[i] );
    }
    
    return ids;
  }
  
  
}
