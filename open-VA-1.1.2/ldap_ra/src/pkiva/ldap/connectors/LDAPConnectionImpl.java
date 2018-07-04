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

import javax.resource.NotSupportedException;
import javax.resource.ResourceException;
import javax.resource.cci.Connection;
import javax.resource.cci.ConnectionMetaData;
import javax.resource.cci.Interaction;
import javax.resource.cci.LocalTransaction;
import javax.resource.cci.ResultSetInfo;
import javax.resource.spi.ManagedConnection;

public class LDAPConnectionImpl implements Connection
{
  
  protected static final String CLOSED_ERROR = "Connection closed";
  private static final String TRANSACTIONS_NOT_SUPPORTED ="Local transactions not supported";
  private static final String RESULT_SETS_NOT_SUPPORTED =	"Result sets not supported";
  protected boolean valid;
  
  private ManagedConnection mc;
  
  public LDAPConnectionImpl(ManagedConnection mc)
  {
    super();
    pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + " is INITING. ManagedConnection: " + mc);
    this.mc = mc;
    valid = true;
  }
  
  void invalidate()
  {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + " is being INVALIDATED. valid: " + valid);
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + "------------------------------------------");
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + "------------------------------------------");

    mc = null;
    valid = false;
  }
  
  public Interaction createInteraction() throws ResourceException
  {
    pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + " is creating Interaction. valid: " + valid);
    if (valid)
      return new LDAPInteractionImpl(this);
    else
      throw new ResourceException(CLOSED_ERROR);
  }
  
  public LocalTransaction getLocalTransaction() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPConnectionImpl " + this + " ::getLocalTransaction.valid: " + valid);
    throw new NotSupportedException(TRANSACTIONS_NOT_SUPPORTED);
  }
  
  public ConnectionMetaData getMetaData() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPConnectionImpl " + this + " ::getMetaData.valid: " + valid);
    if (valid)
      return new LDAPConnectionMetaDataImpl();
    else
      throw new ResourceException(CLOSED_ERROR);
  }
  
  public ResultSetInfo getResultSetInfo() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPConnectionImpl " + this + " ::getResultSetInfo.valid: " + valid);
    throw new NotSupportedException(RESULT_SETS_NOT_SUPPORTED);
  }
  
  public void close() throws ResourceException
  {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("%% " + this + " is being CLOSED. valid: " + valid);
    if (valid) ((LDAPManagedConnectionImpl) mc).close();
  }
  
}
