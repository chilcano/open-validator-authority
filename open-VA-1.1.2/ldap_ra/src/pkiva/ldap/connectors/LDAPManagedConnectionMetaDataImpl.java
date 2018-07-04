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
package pkiva.ldap.connectors;

import javax.resource.ResourceException;
import javax.resource.cci.ConnectionMetaData;
import javax.resource.spi.ManagedConnectionMetaData;

public class LDAPManagedConnectionMetaDataImpl implements ManagedConnectionMetaData
{
  
  /*
javax.resource.spi.ApplicationServerInternalException: Unable to get a connection for LDAPConnector_connectors/LDAP/ConnectionFactories connection pool:

weblogic.common.resourcepool.ResourceLimitException: No resources currently available in pool LDAPConnector_connectors/LDAP/ConnectionFactories to allocate to applications, please increase the size of the pool and retry..
        at weblogic.common.resourcepool.ResourcePoolImpl.reserveResource(ResourcePoolImpl.java:451)
        at weblogic.connector.common.internal.ConnectionPool.reserveResource(ConnectionPool.java:485)

  */
  //private static final int MAX_CONNECTIONS = 1;
  private static final int MAX_CONNECTIONS = 10;
  
  private ConnectionMetaData cxMetaData;
  
  public LDAPManagedConnectionMetaDataImpl(ConnectionMetaData cxMetaData)
  {
    super();
    this.cxMetaData = cxMetaData;
  }
  
  public String getEISProductName() throws ResourceException
  {
    return cxMetaData.getEISProductName();
  }
  
  public String getEISProductVersion() throws ResourceException
  {
    return cxMetaData.getEISProductVersion();
  }
  
  public int getMaxConnections() throws ResourceException
  {
    return MAX_CONNECTIONS;
  }
  
  public String getUserName() throws ResourceException
  {
    return cxMetaData.getUserName();
  }
  
}
