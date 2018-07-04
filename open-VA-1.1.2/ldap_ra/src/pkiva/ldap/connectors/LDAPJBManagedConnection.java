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

import java.util.ArrayList;
import javax.resource.ResourceException;
import javax.resource.spi.LocalTransaction;
import javax.resource.spi.ManagedConnectionMetaData;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ConnectionEvent;
import javax.resource.spi.ConnectionEventListener;
import javax.security.auth.Subject;
import javax.transaction.xa.XAResource;
import java.io.PrintWriter;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version $Revision: 1.5 $
 */
public class LDAPJBManagedConnection implements ManagedConnection
{
   ArrayList listeners = new ArrayList();
   LDAPJBDirContextImpl conn;

   /** Creates new FSManagedConnection */
   public LDAPJBManagedConnection(Subject subject,
      LDAPJBRequestInfo fsInfo)
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% ctor, fsInfo="+fsInfo);
   }

   public void addConnectionEventListener(ConnectionEventListener connectionEventListener)
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% addConnectionEventListener, listener="+connectionEventListener);
      listeners.add(connectionEventListener);
   }
   public void removeConnectionEventListener(ConnectionEventListener connectionEventListener)
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% removeConnectionEventListener, listener="+connectionEventListener);
      listeners.remove(connectionEventListener);
   }

   public void associateConnection(Object obj) throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% associateConnection, obj="+obj);
      conn = (LDAPJBDirContextImpl) obj;
      conn.setManagedConnection(this);
   }

   public void cleanup() throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% cleanup");
   }
   
   public void destroy() throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% destroy");
   }
   
   public Object getConnection(Subject subject, ConnectionRequestInfo info)
      throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getConnection, subject="+subject+", info="+info);
      if( conn == null )
         conn = new LDAPJBDirContextImpl(this);
      return conn;
   }

   public LocalTransaction getLocalTransaction() throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getLocalTransaction");
      return null;
   }
   
   public ManagedConnectionMetaData getMetaData() throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getMetaData");
      return new LDAPJBManagedConnectionMetaData();
   }
   
   public XAResource getXAResource() throws ResourceException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getXAResource");
      return null;
   }

   public PrintWriter getLogWriter() throws ResourceException
   {
      return null;
   }
   public void setLogWriter(PrintWriter out) throws ResourceException
   {
   }

   protected void close()
   {
      ConnectionEvent ce = new ConnectionEvent(this, ConnectionEvent.CONNECTION_CLOSED);
      ce.setConnectionHandle(conn);
      fireConnectionEvent(ce);
   }

   protected void fireConnectionEvent(ConnectionEvent evt)
   {
      for(int i=listeners.size()-1; i >= 0; i--)
      {
         ConnectionEventListener listener = (ConnectionEventListener) listeners.get(i);
         if(evt.getId() == ConnectionEvent.CONNECTION_CLOSED)
            listener.connectionClosed(evt);
         else if(evt.getId() == ConnectionEvent.CONNECTION_ERROR_OCCURRED)
            listener.connectionErrorOccurred(evt);
      }
   }
}
