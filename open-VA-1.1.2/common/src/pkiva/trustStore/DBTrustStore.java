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
package pkiva.trustStore;

import java.util.*;
import java.sql.*;
import javax.sql.*;
import pkiva.exceptions.*;
import pkiva.services.*;
import pkiva.validation.crl.*;

public class DBTrustStore extends TrustStore
{
  /** Datasource name to use */
  public static final String DS_NAME = "java:/EpsilonDS";
  
  protected static final String BASE_SELECT = "select BASE, QUALIFIER, PRINCIPAL, CREDENTIALS, CREDENTIALTYPE, DPTYPE from PKI_VA_TRUSTSTORE";
  
  protected static final String PLAIN_CREDENTIAL_TYPE = "plain";
  
  public DBTrustStore()
  {
    super();
  }
  
  public String getPlainPassword( ) throws TrustStoreException
  {
    // get Parameters
    // in
    String base = (String) parameters.get( BASE );
    String qualifier = (String) parameters.get( QUALIFIER );
    String principal = (String) parameters.get( PRINCIPAL );
    String dpType = (String) parameters.get( DPTYPE );
    // out
    String credentials = null;
    String credentialType = null;
    
    Connection conn = null;
    Statement stm = null;
    ResultSet rs = null;
    try
    {
      conn = getConnection();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Got Connection:" + conn);
      
      // select DB & string comparisons based on dptype
      stm = conn.createStatement();
      String query = buildQuery(base, qualifier, principal, dpType);
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Querying:" + query);
      rs = stm.executeQuery( query );
      
      if ( rs.next())
      {
        pkiva.log.LogManager.getLogger(this.getClass()).debug("base:" + rs.getString( BASE ));
        pkiva.log.LogManager.getLogger(this.getClass()).debug("qualifier:" + rs.getString( QUALIFIER ));
        pkiva.log.LogManager.getLogger(this.getClass()).debug("principal:" + rs.getString( PRINCIPAL ));
        pkiva.log.LogManager.getLogger(this.getClass()).debug("dpType:" + rs.getString( DPTYPE ));
        credentials = rs.getString( CREDENTIALS );
        pkiva.log.LogManager.getLogger(this.getClass()).debug("credentials:" + credentials);
        credentialType = rs.getString( CREDENTIALS_TYPE );
        pkiva.log.LogManager.getLogger(this.getClass()).debug("credentialType:" + credentialType);
      }
      
      if ( rs.next())
      {
        pkiva.log.LogManager.getLogger(this.getClass()).warn("More than one record matches query:" + query);
      }
      
    }
    catch (SQLException sqle)
    {
      // todo: reintentos en caso de conexion cerrada:
      // SQLError: 17008 sqle.getErrorCode() 
      // http://www.cs.fsu.edu/~cop4710/classes/oracle/jdbc/dbaccess/Messages_es.properties.
      // ORA-17008=Conexi\u00f3n cerrada
      pkiva.log.LogManager.getLogger(this.getClass()).error("Exception getting Password.", sqle);
      pkiva.log.LogManager.getLogger(this.getClass()).error("Last SQLException SQLState:" + sqle.getSQLState());
      pkiva.log.LogManager.getLogger(this.getClass()).error("Last SQLException ErrorCode:" + sqle.getErrorCode());
      throw new TrustStoreException( "DB Access Error.", sqle);
    }
    finally
    {
      try
      {rs.close();}
      catch (Exception e)
      {}
      try
      {stm.close();}
      catch (Exception e)
      {}
      try
      {conn.close();}
      catch (Exception e)
      {}
    }
    
    
    // decode credentials based on credentialsType
    String password = decodeCredentials( credentials, credentialType );
    if ( password == null )
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Credential not found");
    
    // return credentials as String
    return password;
  }
  
  protected Connection getConnection( ) throws SQLException
  {
    try
    {
      DataSource ds = (DataSource) ServiceLocator.getInstance().lookup(DS_NAME);
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Got Datasource:" + ds);
     
      return ds.getConnection();
    }
    catch ( NullPointerException e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("No connection available from pool:" + DS_NAME);
      throw new SQLException ( "No connection available from pool:" + DS_NAME );
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("JNDI lookup error.", e);
      throw new SQLException ( "Error getting DataSource from JNDI: " + e.getMessage() );
    }
    
    // Prueba sin WL
    /*
    try
    {
      Class.forName("oracle.jdbc.driver.OracleDriver");
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Driver error", e);
      throw new SQLException( e.getMessage() );
    }
    return DriverManager.getConnection("jdbc:oracle:thin:@enow3500:1522:DES","epsilon","epsilon");
    */
    
  }
  
  // BASE (not null), QUALIFIER (null), PRINCIPAL (not null), CREDENTIALS (not null), CREDENTIALTYPE (null), DPTYPE (null)
  protected String buildQuery(String base, String qualifier, String principal, String dpType ) throws TrustStoreException
  {
    StringBuffer querySB = new StringBuffer( BASE_SELECT );
    querySB.append( " where " ).append( BASE ).append( "='" ).append( base ).append( "' and " );
    querySB.append( PRINCIPAL ).append( "='" ).append( principal ).append( "'" );
    
    if ( dpType != null )
    {
      querySB.append( " and " ).append( DPTYPE ).append( "='" ).append( dpType ).append( "'" );

      if ( IssuingDistributionPoint.URI_DPTYPE.equals( dpType ) )
        querySB.append( " and " ).append( QUALIFIER ).append( "='" ).append( qualifier ).append( "'" );
      else if ( IssuingDistributionPoint.INCOMPLETE_DPTYPE.equals( dpType ) )
        ;
      else
        throw new TrustStoreException( "Unknown dpType: " + dpType );
    }
    
    
    return querySB.toString();
  }
  
  protected String decodeCredentials( String credentials, String credentialsType ) throws TrustStoreException
  {
    if ( credentialsType == null )
      return credentials;
    
    if ( PLAIN_CREDENTIAL_TYPE.equalsIgnoreCase( credentialsType ) )
      return credentials;
    else
      throw new TrustStoreException( "Unknown credentials Type: " + credentialsType );
    
  }
  
}
