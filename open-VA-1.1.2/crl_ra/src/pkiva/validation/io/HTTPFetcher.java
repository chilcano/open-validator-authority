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

public class HTTPFetcher extends GenericFetcher
{
  
  public HTTPFetcher( String loc, Properties props )
  {
    super( loc, props );
  }
  
  public java.security.cert.X509CRL getCRL() throws FetchingException
  {
	long time = 0;
    try
    {
      InputStream is = getSuitableInputStream();
      if ( pkiva.log.LogManager.isInfoEnabled(this.getClass()) )
        pkiva.log.LogManager.getLogger(this.getClass()).info(new StringBuffer().append("HTTPFetcher IStream for loc:[")
                .append(location).append("]::").append(is).toString());
      CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");

	  time = System.currentTimeMillis();

      X509CRL crl = (X509CRL)cf.generateCRL(is);

      time = System.currentTimeMillis() - time;
      if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
		  pkiva.log.LogManager.getLogger(this.getClass()).info(new StringBuffer(location).append(" CRL got in (ms):").append(time).toString());

	  return crl;
    }
    catch ( Exception e )
    {
      time = (time == 0) ? 0 : System.currentTimeMillis() - time;
      if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
		  pkiva.log.LogManager.getLogger(this.getClass()).info(new StringBuffer(location).append(" CRL ERROR in (ms):").append(time).toString());
      throw new FetchingException( "Error getting CRL via HTTP ", e );
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
