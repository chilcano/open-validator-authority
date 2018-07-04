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
package pkiva.validation.crl;
//TODO: implementar MBean para Properties
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public  class CRLLocationStore
{
  
  public static String HTTP_PROXY_HOST="proxyHost";
  public static String HTTP_PROXY_PORT="proxyPort";
  public static String HTTP_PROXY_USER="proxyUser";
  public static String HTTP_PROXY_PWD="proxyPwd";
  
  private static Map m_locations=null;
  private static Map m_props=null;
  
  private static CRLLocationStore instance;
  static
  {
    instance=new CRLLocationStore();
    instance.init();
  }
  
  private CRLLocationStore()
  {
  }
  
  private void init()
  {
    m_locations=new HashMap();
    m_props=new HashMap();
    m_locations.put("CN=e-xtendnow Class 3 CA test, O=e-xtendnow","http://pilotonsitecrl.ace.es/extendnowITClass3/LatestCRL.crl");
    m_locations.put("OU=Entrust PKI Demonstration Certificates, O=Entrust, C=US","http://sac2k400/pruebaSabadell3/crlCertificadoNoRevocado.der");
  }
  
  synchronized public static CRLLocationStore getInstance()
  {
    CRLLocationStore o=new CRLLocationStore();
    o.m_locations=m_locations;
    o.m_props=m_props;
    return o;
  }
  
  public String getLocation(String CA)
  {
    return (String)m_locations.get(CA);
  }
  
  public Properties getProperties(String CA)
  {
    return (Properties)m_props.get(CA);
  }
  
  public void setValue(String sKey, String value)
  {
    instance.m_locations.put(sKey,value);
  }
  public String getValue(String sKey)
  {
    return (String)instance.m_locations.get(sKey);
  }
  public void deleteValue(String sKey)
  {
    instance.m_locations.remove(sKey);
  }
  public void printValue(String sKey)
  {
    System.out.println((String)instance.m_locations.get(sKey));
  }
}
