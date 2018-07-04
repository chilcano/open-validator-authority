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
package pkiva.validation.connectors;


import javax.naming.NamingException;
import javax.naming.Reference;
import javax.resource.ResourceException;
import javax.resource.cci.Connection;
import javax.resource.cci.ConnectionFactory;
import javax.resource.cci.ConnectionSpec;
import javax.resource.cci.RecordFactory;
import javax.resource.cci.ResourceAdapterMetaData;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ManagedConnectionFactory;

public class CertValidationChannelConnectionFactoryImpl implements ConnectionFactory
{
  
  private Reference reference;
  private ConnectionManager cm;
  private ManagedConnectionFactory mcf;
  
  
  public CertValidationChannelConnectionFactoryImpl(ManagedConnectionFactory mcf,ConnectionManager cm)
  {
    super();
    this.mcf = mcf;
    this.cm = cm;
  }
  public Connection getConnection() throws ResourceException
  {
    return (Connection) cm.allocateConnection(mcf, null);
  }
  
  public Connection getConnection(ConnectionSpec connectionSpec) throws ResourceException
  {
    return getConnection();
  }
  
  //abstract public RecordFactory getRecordFactory() throws ResourceException ;
  public RecordFactory getRecordFactory() throws ResourceException
  {
    return new CertValidationChannelRecordFactoryImpl();
  }
  
  public ResourceAdapterMetaData getMetaData() throws ResourceException
  {
    return new CertValidationChannelResourceAdapterMetaDataImpl();
  }
  
  public void setReference(Reference reference)
  {
    this.reference = reference;
  }
  
  public Reference getReference() throws NamingException
  {
    return reference;
  }
  
}
