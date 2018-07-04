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

import java.net.*;
import java.io.*;
import java.util.Properties;

/**
 * Clase que captura información desde un site http.
 */
public class HTTPInputStream extends InputStream{

    public static String HTTP_PROXY_HOST="proxyHost";
	public static String HTTP_PROXY_PORT="proxyPort";
	public static String HTTP_PROXY_USER="proxyUser";
	public static String HTTP_PROXY_PWD="proxyPwd";
	
	String m_uri = "";
	Properties m_props=null;
	DataInputStream m_adaptee;
	URLConnection urlConn;
	
	String m_prevproxySet;
	String m_prevproxyPort;
	String m_prevproxyHost;	
	
	boolean m_proxySet=false;
	
    public HTTPInputStream(){};

    /**
     * Constructor
     *
     * @param   strUri  uri to connect to
     * @return
     */
    public HTTPInputStream(String strUri,Properties props) throws IOException{
        this.m_uri=strUri;
        m_props=props;
        open();
    }

	private void setUri(String strUri) {
		this.m_uri=strUri;
		
	}

 	private void setProperties(Properties props){
 		m_props=props;
	}

/**
 * Realiza la conexión con la uri especificada.
 *
 * @param
 * @return
 * @exception CertificateValidationErrorException Se lanza la excepción en caso de suceder algún tipo
 * de error en la conexión:
 * 		Si no se puede construir la URL -> URI_ERROR_01
 *		Si no se puede conectar con la URL -> URI_ERROR_02
 *		Si no se pueden obtener datos de la URL -> URI_ERROR_03
 *		Si existe algún problema al obtener la conexión -> URI_ERROR_04
 */

	public void open() throws   IOException{
		try{
			URL url = new URL(m_uri);
			urlConn = url.openConnection();

		  if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))
			{

				try
				{
				  long time = System.currentTimeMillis();
				/*
				Two Java security properties control the TTL values used for positive and negative host name resolution caching: 

				networkaddress.cache.ttl (default: -1) 
				Indicates the caching policy for successful name lookups from the name service. The value is specified as as integer to indicate the number of seconds to cache the successful lookup. 
				A value of -1 indicates "cache forever". 

				networkaddress.cache.negative.ttl (default: 10) 
				Indicates the caching policy for un-successful name lookups from the name service. The value is specified as as integer to indicate the number of seconds to cache the failure for un-successful lookups. 
				A value of 0 indicates "never cache". A value of -1 indicates "cache forever". 
				*/


				  pkiva.log.LogManager.getLogger(this.getClass()).info("Host Name Resolution:" + InetAddress.getByName(url.getHost()) );
				  pkiva.log.LogManager.getLogger(this.getClass()).info("networkaddress.cache.ttl (def: forever):" + System.getProperty("networkaddress.cache.ttl") );
				  pkiva.log.LogManager.getLogger(this.getClass()).info("networkaddress.cache.negative.ttl (def: 10s):" + System.getProperty("networkaddress.cache.negative.ttl") );
				  
				  time = System.currentTimeMillis() - time;
				  pkiva.log.LogManager.getLogger(this.getClass()).info(new StringBuffer("NSLook up in (ms):").append(time).toString());

				}
				catch ( Throwable t )
				{
					pkiva.log.LogManager.getLogger(this.getClass()).debug("NSLooking up ", t);
				}
			} // end if (pkiva.log.LogManager.isInfoEnabled(this.getClass()))

			//pkiva.log.LogManager.getLogger(this.getClass()).debug("b4 openCon");
			//pkiva.log.LogManager.getLogger(this.getClass()).debug("b4 enableProxy");
			enableProxy(urlConn);
			if(urlConn != null){


				urlConn.setDoOutput(false);
				urlConn.setDoInput(true);
				urlConn.setUseCaches(false);
				urlConn.setRequestProperty("user-agent","Mozilla/4.06 [en] (Win98; I)");

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

				InputStream inStreamRaw = null;
				pkiva.log.LogManager.getLogger(this.getClass()).debug("b4 getInputStream: " + new java.util.Date());
				inStreamRaw = urlConn.getInputStream();
				pkiva.log.LogManager.getLogger(this.getClass()).debug("b4 DataInputStream" + new java.util.Date());
				m_adaptee = (new DataInputStream(inStreamRaw));
				pkiva.log.LogManager.getLogger(this.getClass()).debug("Connection opened" + new java.util.Date());

			}
		}catch (MalformedURLException mue){
			close();
			throw new IOException ("La URI está mal formada: " + m_uri);
		}catch(IOException ioe){
			close();
			pkiva.log.LogManager.getLogger(this.getClass()).debug("IOException re-thrown: ", ioe);
			//throw new IOException ("Error al acceder a la uri " + m_uri + ioe.getMessage());
			throw ioe;
		}
			
	}

 private void enableProxy(URLConnection urlConn){
 	if(m_props!=null){
            String proxyHost=m_props.getProperty(HTTP_PROXY_HOST,null);
            if( proxyHost!=null && !proxyHost.equals("") && urlConn!=null){
		m_proxySet=true;
		m_prevproxySet=(String)System.getProperties().get("proxySet");
		m_prevproxyPort=(String)System.getProperties().get("proxyPort");
		m_prevproxyHost=(String)System.getProperties().get("proxyHost");
		
		System.getProperties().put("proxySet","true");
		System.getProperties().put("proxyPort",m_props.getProperty(HTTP_PROXY_PORT));
		System.getProperties().put("proxyHost",proxyHost);
		String proxyUser=m_props.getProperty(HTTP_PROXY_USER);
		String proxyPwd=m_props.getProperty(HTTP_PROXY_PWD);
		
		urlConn.setRequestProperty("Proxy-Authorization",
			(new sun.misc.BASE64Encoder()).encode(
				(proxyUser+":"+proxyPwd).getBytes()
			)
		);		
            }
        }
 } 
 
 private void disableProxy(){
 	if (m_proxySet){
 		System.getProperties().put("proxySet",m_prevproxySet);
		System.getProperties().put("proxyPort",m_prevproxyPort);
		System.getProperties().put("proxyHost",m_prevproxyHost);
	}
 }
 	
/**
 * Realiza la comprobación de si el stream se encuentra disponible.
 *
 * @param
 * @return entero con el resultado (@see#java.io.InputStream)
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error.
 */
	public int available() throws IOException{
		return m_adaptee.available();
	}
/**
 * Cierra la conexión y libera los recursos.
 *
 * @param
 * @return
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al liberar los recursos.
 */
	public void close() throws IOException{
		if(m_adaptee!=null) m_adaptee.close();
		disableProxy();
	}
/**
 * Marca el límite de lectura(@see#java.io.InputStream).
 *
 * @param readlimit Límite en bytes.
 * @return
 */

	public void mark(int readlimit)	{
		m_adaptee.mark(readlimit);
	}
/**
 * Determina si soporta la colocación de marcas
 * (@see java.io.InputStream).
 *
 * @param
 * @return true en caso de estar soportado, false, en caso contrario.
 */
	public boolean markSupported(){
		return 	m_adaptee.markSupported();
	}

/**
 * Realiza la lectura de un caracter(o byte).
 *
 * @param
 * @return entero con el carácter realizado.
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al leer.
 */

	public int read() throws IOException
	{
		return m_adaptee.read();
	}

/**
 * Realiza la lectura de un array de bytes.
 *
 * @param b Es el parámetro donde se realizará la lectura de los mismos.
 * @return entero con el número de bytes leidos.
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al leer.
 */

	public int read(byte[] b) throws IOException
	{
		return m_adaptee.read(b);
	}
/**
 * Realiza la lectura de un array de bytes con un salto según se especifica
 * en los parámetros.
 *
 * @param b Es el parámetro donde se realizará la lectura de los mismos.
 * @param off Número de bytes a partir de los cuales se realizará la lectura.
 * @param len Número de bytes que se quieren leer.
 * @return entero con el número de bytes leidos.
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al leer.
 */

	public int read(byte[] b, int off, int len) throws IOException	{
		return m_adaptee.read(b,off,len);
	}
/**
 * Realiza un reset de la entrada, tal y conforme se especifica en
 * la interfaz java.io.InputStream.
 *
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al leer.
 */

	public void reset() throws IOException	{
		m_adaptee.reset();
	}
/**
 * Realiza la omisión de un número de bytes especificado por
 * el parámetro.
 *
 * @param n es el número de bytes que se quieren saltar (@see#java.io.InputStream).
 * @return El resultado tal y conforme se especifica en la interfaz java.io.InputStream.
 * @exception Se lanza la excepción en caso de suceder algún tipo
 * de error al leer.
 */
	public long skip(long n) throws IOException {
		return m_adaptee.skip(n);
	}

}
