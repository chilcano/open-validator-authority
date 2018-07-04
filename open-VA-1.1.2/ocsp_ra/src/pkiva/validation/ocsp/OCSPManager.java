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

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.cert.*;
import java.security.*;
import org.bouncycastle.ocsp.*;

import pkiva.exceptions.*;
import pkiva.validation.ocsp.connectors.*;

public class OCSPManager
{ //Singleton
  
  static private OCSPManager m_instance = new OCSPManager();
  
  static public OCSPManager instance()
  {
    return m_instance;
  }
  
  protected OCSPManager()
  {
  }
  
  /**
   * find out the validation from an *<b>incomplete</b>* certificate chain.
   * if chain is revoked, throws OCSPRevokedChainException 
   * in case a server error happens, throws OCSPServerException with error status
   * in case another error happens, throws OCSPValidationException with detail message
   */
  public OCSPValidationResponse validate( X509Certificate[] chain ) throws CertPathValidatorException
  {
    try
    {
      if ( ( chain == null ) || ( chain.length == 0 ) )
      {
        throw new OCSPValidationException( new IllegalArgumentException( "Can't validate an empty chain") );
      }
      /*if ( chain.length == 1 )
      {
        throw new OCSPValidationException( new IllegalArgumentException( "Can't validate chain with only one cert") );
      }*/
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Validamos via OCSP cadena de longitud::" + chain.length);
      // chain.length >= 1

      OCSPConnectionData ocspConData = new OCSPConnectionData ( chain );
      
      X509Certificate signcert = ocspConData.getSignCert( );// certificado para firmar
      PrivateKey signkey = null;
      pkiva.log.LogManager.getLogger(this.getClass()).debug("certificado para firmar::" + signcert);
      if ( signcert == null )
      {
        // if there is no alias, don't sign request
        //throw new OCSPValidationException( new IllegalArgumentException( "Can't get sign cert") );
      }
      else
      {
        signkey = ocspConData.getSignKey( ); // clave del certificado para firmar
        pkiva.log.LogManager.getLogger(this.getClass()).debug("clave del certificado para firmar::" + signkey);
        if ( signkey == null )
          // if there is no alias, don't sign request
          //throw new OCSPValidationException( new IllegalArgumentException( "Can't get sign key") );
          signcert = null;
      }

      String url = ocspConData.getURL( );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("URL::" + url);
      if ( url == null )
        throw new OCSPValidationException( new IllegalArgumentException( "Can't get url string") );
      
      String signingAlgorithm = ocspConData.getSigningAlgorithm( );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("signingAlgorithm::" + signingAlgorithm);
      if ( signingAlgorithm == null )
        throw new OCSPValidationException( new IllegalArgumentException( "Can't get signingAlgorithm") );
      
      String provider = ocspConData.getProvider( );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("provider::" + provider);
      if ( provider == null )
        throw new OCSPValidationException( new IllegalArgumentException( "Can't get provider") );
      
      X509Certificate ocspCert = ocspConData.getResponderCert( );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("certificado del OCSP responder::" + ocspCert);
      if ( ocspCert == null )
        throw new OCSPValidationException( new IllegalArgumentException( "Can't get OCSP Responder cert") );
      //ocspValResp.setOCSPCert ( ocspCert );

      OCSPClient ocspClient = new OCSPClient ( chain );
      byte[] requestData = ocspClient.generateRequest(signcert, signkey, signingAlgorithm, provider);
      
      byte[] ocsprespdata = doRequest(requestData, url);

      StringBuffer msg = new StringBuffer ("OCSP Response from [");
      msg.append(url).append("] for Certificate [");
      msg.append(chain[0].getIssuerDN().getName()).append("-").append(chain[0].getSerialNumber()).append("]:\n");
      msg.append(new String(ocsprespdata));
      String msgSt = msg.toString();
      pkiva.log.LogManager.getLogger(this.getClass()).info(msgSt);
      //pkiva.log.AuditManager.getAuditer(this.getClass()).audit(msgSt);

      OCSPResp resp = new OCSPResp(ocsprespdata);
      //ocspValResp.setOCSPData ( ocspData );
      
      int respStatus = resp.getStatus();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Codigo de respuesta del servidor OCSP::" + respStatus);
      checkServerStatus( respStatus );
      
      RespData respData = checkResponse( resp, ocspCert, provider );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("La respuesta del servidor OCSP es correcta");
      
      SingleResp [] responses = respData.getResponses();
      if (responses==null)
        throw new OCSPValidationException("La respuesta del OCSP no contiene certificados de cliente");
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Numero de respuestas simples del servidor OCSP ::" + responses.length);
      //if (responses.length != (chain.length - 1) ) // quitamos el trustAnchor
      if (responses.length != (chain.length) ) // ya no quitamos el trustAnchor
        throw new OCSPValidationException("El numero de certificados en la respuesta del OCSP no es igual a los de la petición");
      
      OCSPValidationInfo ocspInfo = ocspClient.checkChainStatus( responses, ocsprespdata, ocspCert );

      OCSPValidationResponse ocspValResp = new OCSPValidationResponse( OCSPValidationResponse.OK );
      ocspValResp.setInfo ( ocspInfo );

      return ocspValResp;
    }
    // Cambios en el lanzamiento de exceptions (Ver el problema en PKIXMasterCertPathValidator.java:116)
//    catch (  OCSPServerException e )
//    {
//      pkiva.log.LogManager.getLogger(this.getClass()).error("Server Error validating chain via OCSP", e);
//      throw e;
//    }
//    catch ( CertificateChainRevocationException e )
//    {
//      pkiva.log.LogManager.getLogger(this.getClass()).info("Revoked chain via OCSP");
//      throw e;
//    }
//    catch ( OCSPValidationException ve )
//    {
//      pkiva.log.LogManager.getLogger(this.getClass()).error("Internal Error validating chain via OCSP", ve);
//      throw ve;
//    }
    catch (  OCSPServerException e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Server Error validating chain via OCSP", e);
      throw new CertPathValidatorException(e.getMessage(), e);
    }
    catch ( CertificateChainRevocationException e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).info("Revoked chain via OCSP");
      throw new CertPathValidatorException(e.getMessage(), e);
    }
    catch ( OCSPValidationException e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Internal Error validating chain via OCSP", e);
      throw new CertPathValidatorException(e.getMessage(), e);
    }
    catch ( Throwable t )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Internal Error validating chain via OCSP", t);
      OCSPValidationException e = new OCSPValidationException( "Internal Error validating chain via OCSP", t );
      throw new CertPathValidatorException(e.getMessage(), e);
    }
  }
  
  protected byte[] doRequest( byte[] ocspdata, String urlSt ) throws OCSPValidationException
  {
    try
    {
      // Timeout management for URLConnection. See for details:
      // http://forum.java.sun.com/thread.jsp?thread=17410&forum=11&message=464595
      // http://java.sun.com/j2se/1.4/docs/guide/net/properties.html
      if ( System.getProperty ( "sun.net.client.defaultConnectTimeout" ) == null )
      {
        System.setProperty ( "sun.net.client.defaultConnectTimeout", String.valueOf ( 30*1000 ) ); // 30 seconds -> millis
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Property [sun.net.client.defaultConnectTimeout (millis)] set to::" + System.getProperty ( "sun.net.client.defaultConnectTimeout" ));
      }
      if ( System.getProperty ( "sun.net.client.defaultReadTimeout" ) == null )
      {
        System.setProperty ( "sun.net.client.defaultReadTimeout", String.valueOf ( 30*1000 ) ); // 30 seconds -> millis
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Property [sun.net.client.defaultReadTimeout (millis)] set to::" + System.getProperty ( "sun.net.client.defaultReadTimeout" ));
      }

      // componer la  petición
      URL url = new URL(urlSt);
      
      // ???
      //HttpsURLConnection.setDefaultHostnameVerifier(new myHostNameVerifier());
      HttpURLConnection con = (HttpURLConnection) url.openConnection();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("HttpURLConnection::" + con);
      con.setAllowUserInteraction(false);
      con.setDoInput(true);
      con.setDoOutput(true);
      con.setUseCaches(false);
      con.setFollowRedirects(false);
      con.setRequestMethod("POST");
      con.setRequestProperty("Content-Length", Integer.toString(ocspdata.length));
      con.setRequestProperty("Content-Type", "application/ocsp-request");
      OutputStream os = con.getOutputStream();
      os.write(ocspdata);
      con.connect();
      os.close();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("HTTP response code::" + con.getResponseCode());
      if (con.getResponseCode() != HttpURLConnection.HTTP_OK)
      {
        throw new OCSPValidationException("Petición no aceptada :" + con.getResponseCode());
      }
      
      pkiva.log.LogManager.getLogger(this.getClass()).debug("HTTP response content type::" + con.getContentType());
      if (con.getContentType() == null ||
      !con.getContentType().equals("application/ocsp-response"))
      {
        throw new OCSPValidationException(
        "Content-type en Respuesta Erroneo (no es application/ocsp-response):" + con.getContentType());
      }
      
      pkiva.log.LogManager.getLogger(this.getClass()).debug("HTTP response content length::" + con.getContentLength());
      // [RFC 2560] "The Content-Length header SHOULD specify the length of the response"
      int len = con.getContentLength();
      /*if (len < 1)
      {
        throw new OCSPValidationException( "El mensaje no incluye la respuesta del OCSP. Longitud" + len);
      }*/
      
      InputStream reader = con.getInputStream();
      
      byte[] ocsprespdata = new byte[len];
      int offset = 0;
      int bytes_read;
      while ( (bytes_read = reader.read(ocsprespdata, offset, len - offset)) != -1)
      {
        offset += bytes_read;
        if (offset == len)
        {
          break;
        }
      }
      
      if (offset != len)
      {
        throw new OCSPValidationException("No se puede leer la respuesta entera del OCSP. Bytes leidos:" + offset);
      }
      reader.close();
      con.disconnect();
      
      return ocsprespdata;
    }
    catch ( Exception e )
    {
      throw new OCSPValidationException("Error en la peticion HTTP al servidor OCSP", e);
    }
  }
  
  protected void checkServerStatus( int status ) throws OCSPServerException
  {
    switch (status)
    {
      case OCSPRespStatus.SUCCESSFUL:
        break;
      case OCSPRespStatus.INTERNAL_ERROR:
        throw new OCSPServerException( OCSPServerException.INTERNAL_ERROR );
      case OCSPRespStatus.MALFORMED_REQUEST:
        throw new OCSPServerException( OCSPServerException.MALFORMED_REQUEST );
      case OCSPRespStatus.SIGREQUIRED:
        throw new OCSPServerException( OCSPServerException.SIGREQUIRED );
      case OCSPRespStatus.TRY_LATER:
        throw new OCSPServerException( OCSPServerException.TRY_LATER );
      case OCSPRespStatus.UNAUTHORIZED:
        throw new OCSPServerException( OCSPServerException.UNAUTHORIZED );
      default:
        throw new OCSPServerException(status);
    }
  }
  
  protected RespData checkResponse( OCSPResp resp, X509Certificate ocspCert, String provider ) throws OCSPValidationException
  {
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Comprobando la integridad de la respuesta");
    try
    {
      BasicOCSPResp bresp = null;
    try
    {
      bresp= (BasicOCSPResp) resp.getResponseObject();
    }
    catch (Exception e)
    {
      throw new OCSPValidationException("La respuesta OCSP no contiene un objeto valido de tipo BasicOCSPResponse.", e);
    }
    
    
    if (bresp==null)
      throw new OCSPValidationException("No BasicOCSPResponse encontrado");
    
    if (!bresp.verify(ocspCert.getPublicKey(),provider))
      throw new OCSPException("No se puede verificar la respuesta del servidor OCSP");
    
    X509Certificate [] servercerts = (X509Certificate[])bresp.getCerts(provider);
    
    if ( servercerts != null && servercerts.length != 0 )
      if ( ! servercerts[0].equals(ocspCert) )
        throw new OCSPValidationException("Respuesta OCSP firmada con un certificado desconocido");
    
    RespData respdata=null;
    try
    {
      respdata=bresp.getResponseData();
    }
    catch (Exception e)
    {
      throw new OCSPValidationException("Error extrayendo datos de la respuesta.", e);
    }
    
    if ( respdata == null )
      throw new OCSPValidationException("No hay datos en la respuesta OCSP");
    
    RespID respid=respdata.getResponderId();
    
    if ( ! respid.equals( new RespID( ocspCert.getPublicKey() ) ) && ! respid.equals( new RespID( ocspCert.getSubjectX500Principal() ) ) )
      throw new OCSPValidationException("El ID del Responder no corresponde al del certificado de OCSP");
    
    return respdata;
    }
    catch ( OCSPValidationException e )
    {
      throw e;
    }
    catch ( Exception e )
    {
      throw new OCSPValidationException("Error comprobando la integridad de la respuesta OCSP", e);
    }
  }
  
  
}
