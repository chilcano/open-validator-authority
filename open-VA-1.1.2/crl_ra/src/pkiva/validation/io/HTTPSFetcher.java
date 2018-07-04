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
package pkiva.validation.io;

import java.util.Properties;
import java.security.cert.*;
import java.io.*;
import pkiva.exceptions.*;

import javax.net.ssl.*;

public class HTTPSFetcher extends GenericFetcher
{
  
  public HTTPSFetcher( String loc, Properties props )
  {
    super( loc, props );
  }
  
  public java.security.cert.X509CRL getCRL() throws FetchingException
  {
//      SSLSocketFactory sslSocketFactory = null;
      try {
//          sslSocketFactory = disableSSLChecking();
          InputStream is = getSuitableInputStream();
          pkiva.log.LogManager.getLogger(this.getClass()).info("HTTPSFetcher IStream::" + is);
          CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");

		  long time = System.currentTimeMillis();

          X509CRL crl = (X509CRL) cf.generateCRL(is);

		  time = System.currentTimeMillis() - time;
		  if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
			  pkiva.log.LogManager.getLogger(this.getClass()).info(new StringBuffer(location).append(" CRL got in (ms):").append(time).toString());

          return crl;
      } catch (Exception e) {
          throw new FetchingException("Error getting CRL via HTTP ", e);
      } finally
      {
//          enableSSLChecking(sslSocketFactory);
      }

  }

    private SSLSocketFactory disableSSLChecking() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };

        // Install the all-trusting trust manager
        SSLSocketFactory oldSSLSocketFactory = null;
        try {
            oldSSLSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
            pkiva.log.LogManager.getLogger(this.getClass()).warn("HTTPSFetcher. oldSSLSocketFactory::" + oldSSLSocketFactory);

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory newSSLSocketFactory = sc.getSocketFactory();
            HttpsURLConnection.setDefaultSSLSocketFactory(newSSLSocketFactory);
            pkiva.log.LogManager.getLogger(this.getClass()).warn("HTTPSFetcher. newSSLSocketFactory::" + newSSLSocketFactory);
        } catch (Exception e) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("HTTPSFetcher. Error disabling certificate checking. Ignoring", e);
        }

        // Now you can access an https URL without having the certificate in the truststore
//        try {
//            URL url = new URL("https://hostname/index.html");
//        } catch (MalformedURLException e) {
//        }
//
        return oldSSLSocketFactory;
    }

    private void enableSSLChecking(SSLSocketFactory sslSocketFactory) {
        if (sslSocketFactory != null) {
            pkiva.log.LogManager.getLogger(this.getClass()).warn("HTTPSFetcher. resetting SSLSocketFactory::" + sslSocketFactory);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
        }

    }

    private InputStream getSuitableInputStream( ) throws IOException
  {
//       diriarte: meanwhile firewall changes are performed
//      String file = null;
//      File linuxTmpDir = new File("/tmp/");
//      boolean isLinux = linuxTmpDir.exists();
//      pkiva.log.LogManager.getLogger(this.getClass()).info("isLinux::" + isLinux);
//      if (location.equalsIgnoreCase("http://pilotonsitecrl.ace.es/NetFocusSRLextendnowClass2CATestM/LatestCRL.crl")) {
//          file = isLinux ? "/tmp/pkiva_crls/LatestCRL.crl" : "c:\\dani\\certificados\\LatestCRL.crl";
//      } /*else if (location.equalsIgnoreCase("")) {
//          file = "";
//      }*/
//      pkiva.log.LogManager.getLogger(this.getClass()).info("file::" + file);
//
//      if (file != null) {
//          File test = new File(file);
//          boolean exists = test.exists();
//          pkiva.log.LogManager.getLogger(this.getClass()).info(file + " exists::" + exists);
//          if (exists) {
//              return new FileInputStream(file);
//          }
//      }
      return new HTTPInputStream(location, params);
  }
}
