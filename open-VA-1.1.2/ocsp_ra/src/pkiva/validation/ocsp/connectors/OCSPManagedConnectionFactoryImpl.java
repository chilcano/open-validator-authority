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
package pkiva.validation.ocsp.connectors;

import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Set;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionFactory;
import javax.security.auth.Subject;

public class OCSPManagedConnectionFactoryImpl implements ManagedConnectionFactory
{
  
  private PrintWriter writer;
  
  
  public OCSPManagedConnectionFactoryImpl()
  {
    super();
  }
  
  public Object createConnectionFactory(ConnectionManager cm) throws ResourceException
  {
    return new OCSPConnectionFactoryImpl(this, cm);
  }
  
  public Object createConnectionFactory() throws ResourceException
  {
    return new OCSPConnectionFactoryImpl(this, null);
  }
  
  public ManagedConnection createManagedConnection(Subject subject,ConnectionRequestInfo cxRequestInfo) throws ResourceException
  {
    return new OCSPManagedConnectionImpl();
  }
  
  public ManagedConnection matchManagedConnections(Set connectionSet,Subject subject,ConnectionRequestInfo cxRequestInfo) throws ResourceException
  {
    ManagedConnection match = null;
    Iterator iterator = connectionSet.iterator();
    if (iterator.hasNext())
    {
      match = (ManagedConnection) iterator.next();
    }
    return match;
  }
  
  public void setLogWriter(PrintWriter writer) throws ResourceException
  {
    this.writer = writer;
  }
  
  public PrintWriter getLogWriter() throws ResourceException
  {
    return writer;
  }
  
  public boolean equals(Object other)
  {
    if (other instanceof OCSPManagedConnectionFactoryImpl)
    {
      return true;
    }
    return false;
  }
  
  public int hashCode()
  {
    return 0;
  }
  
}
