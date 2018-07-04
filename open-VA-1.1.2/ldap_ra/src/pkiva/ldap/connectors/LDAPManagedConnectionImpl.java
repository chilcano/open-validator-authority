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

import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Vector;

import javax.resource.NotSupportedException;
import javax.resource.ResourceException;
import javax.resource.spi.ConnectionEvent;
import javax.resource.spi.ConnectionEventListener;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.LocalTransaction;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionMetaData;
import javax.security.auth.Subject;
import javax.transaction.xa.XAResource;

public class LDAPManagedConnectionImpl implements ManagedConnection
{
  
  private static final String TRANSACTIONS_NOT_SUPPORTED_ERROR =	"Transactions not supported";
  protected LDAPConnectionImpl connection;
  private Vector listeners = new Vector();
  private PrintWriter out;
  
  public LDAPManagedConnectionImpl()
  {
    super();
  }
  
  public void close()
  {

//      [org.jboss.resource.connectionmanager.NoTxConnectionManager] Throwable from unregisterConnection
//      java.lang.IllegalStateException: Trying to return an unknown connection2! javax.resource.spi.ConnectionEvent[source=pkiva.ldap.connectors.LDAPManagedConnectionImpl@19ffd6f]
//          at org.jboss.resource.connectionmanager.CachedConnectionManager.unregisterConnection(CachedConnectionManager.java:374)
//      [org.jboss.resource.connectionmanager.NoTxConnectionManager] Unregistered handle that was not registered! javax.resource.spi.ConnectionEvent[source=pkiva.ldap.connectors.LDAPManagedConnectionImpl@19ffd6f] for managedConnection: pkiva.ldap.connectors.LDAPManagedConnectionImpl@19ffd6f

    pkiva.log.LogManager.getLogger(this.getClass()).debug("%% LDAPManagedConnectionImpl is CLOSING " + connection);
    Enumeration list = listeners.elements();
    ConnectionEvent event =	new ConnectionEvent(this, ConnectionEvent.CONNECTION_CLOSED);
    event.setConnectionHandle(connection);
    while (list.hasMoreElements())
    {
      ((ConnectionEventListener) list.nextElement()).connectionClosed(event);
    }
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPManagedConnectionImpl::close.listeners: " + listeners);
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% LDAPManagedConnectionImpl is INVALIDATING " + connection);
      if ( connection != null )
      connection.invalidate();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% LDAPManagedConnectionImpl has INVALIDATED " + connection);

//      2005-03-15 15:47:40,269 INFO  [org.jboss.resource.connectionmanager.CachedConnectionManager] Closing a connection for you.  Please close them yourself: pkiva.ldap.connectors.LDAPConnectionImpl@11ce012
//      java.lang.Exception: STACKTRACE
//          at org.jboss.resource.connectionmanager.CachedConnectionManager.registerConnection(CachedConnectionManager.java:320)
//          at org.jboss.resource.connectionmanager.BaseConnectionManager2.allocateConnection(BaseConnectionManager2.java:477)
//          at org.jboss.resource.connectionmanager.BaseConnectionManager2$ConnectionManagerProxy.allocateConnection(BaseConnectionManager2.java:838)
//          at pkiva.ldap.connectors.LDAPConnectionFactoryImpl.getConnection(Unknown Source)

  }
  
  public Object getConnection(Subject subject,ConnectionRequestInfo cxRequestInfo) throws ResourceException
  {
    connection = new LDAPConnectionImpl(this);
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPManagedConnectionImpl::getConnection.conection: " + connection);
    return connection;
  }
  
  public void destroy() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPManagedConnectionImpl::destroy.conection: " + connection);
    if ( connection != null )
      connection.invalidate();
    connection = null;
    listeners = null;
  }
  
  public void cleanup() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPManagedConnectionImpl::cleanup.conection: " + connection);
    if ( connection != null )
      connection.invalidate();
  }
  
  public void associateConnection(Object connection) throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPManagedConnectionImpl::associateConnection.conection: " + connection);
  }
  
  public void addConnectionEventListener(ConnectionEventListener listener)
  {
    listeners.add(listener);
  }
  
  public void removeConnectionEventListener(ConnectionEventListener listener)
  {
    listeners.remove(listener);
  }
  
  public XAResource getXAResource() throws ResourceException
  {
    throw new NotSupportedException(TRANSACTIONS_NOT_SUPPORTED_ERROR);
  }
  
  public LocalTransaction getLocalTransaction() throws ResourceException
  {
    throw new NotSupportedException(TRANSACTIONS_NOT_SUPPORTED_ERROR);
  }
  
  public ManagedConnectionMetaData getMetaData() throws ResourceException
  {
    return new LDAPManagedConnectionMetaDataImpl(connection.getMetaData());
  }
  
  public void setLogWriter(PrintWriter out) throws ResourceException
  {
    this.out = out;
  }
  
  public PrintWriter getLogWriter() throws ResourceException
  {
    return out;
  }
  
}
