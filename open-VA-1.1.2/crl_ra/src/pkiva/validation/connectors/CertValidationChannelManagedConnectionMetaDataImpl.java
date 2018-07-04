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

import javax.resource.ResourceException;
import javax.resource.cci.ConnectionMetaData;
import javax.resource.spi.ManagedConnectionMetaData;

public class CertValidationChannelManagedConnectionMetaDataImpl
implements ManagedConnectionMetaData
{
  
  private static final int MAX_CONNECTIONS = 1;
  
  private ConnectionMetaData cxMetaData;
  
  public CertValidationChannelManagedConnectionMetaDataImpl(ConnectionMetaData cxMetaData)
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
