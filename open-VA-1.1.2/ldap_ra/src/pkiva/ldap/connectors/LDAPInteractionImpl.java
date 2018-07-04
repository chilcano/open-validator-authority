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

import java.security.cert.*;
import javax.resource.NotSupportedException;
import javax.resource.ResourceException;
import javax.resource.cci.Connection;
import javax.resource.cci.Interaction;
import javax.resource.cci.InteractionSpec;
import javax.resource.cci.Record;
import javax.resource.cci.IndexedRecord;
import javax.resource.cci.ResourceWarning;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.*;

import pkiva.ldap.*;


public class LDAPInteractionImpl implements Interaction
{
  //protected static String CHANNELSTR="";
  //private static final int CERTIFICATE_FIELD = 0;
  private static final int ELEMENT_FIELD = 0;
  private static final String CLOSED_ERROR = "Connection closed";
  private static final String INVALID_FUNCTION_ERROR = "Invalid function";
  private static final String INVALID_INPUT_ERROR = "Invalid input record for function";
  private static final String INVALID_OUTPUT_ERROR = "Invalid output record for function";
  private static final String EXECUTE_WITH_INPUT_RECORD_ONLY_NOT_SUPPORTED = "execute() with input record only not supported";
  
  private Connection connection;
  private boolean valid;
  
  public LDAPInteractionImpl(Connection connection)
  {
    super();
//    pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPInteractionImpl::init.connection: " + connection);
    this.connection = connection;
    valid = true;
  }
  
  public void close() throws ResourceException
  {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%%%%%%%%%%%%%%%% LDAPInteractionImpl::close.connection: " + connection);
    connection = null;
    valid = false;
  }
  
  public Connection getConnection()
  {
    return connection;
  }
  
  public boolean execute(InteractionSpec ispec, Record input, Record output) throws ResourceException
  {
    
    if (valid)
    {
      String strOperation="";
      try
      {
        java.lang.reflect.Method m=ispec.getClass().getMethod("getFunctionName",new Class[0]);
        strOperation=(String)m.invoke(ispec,new Object[0]);
      }
      catch(Exception e)
      {
        pkiva.log.LogManager.getLogger(this.getClass()).error("Exception in resource adapter when invoking getFunctionName", e);
        // javax.resource.ResourceException does not support chained Exceptions
        throw new ResourceException("Exception in resource adapter when invoking getFunctionName:" + e.getMessage());
      }
      
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Request to execute. Function Name: " + strOperation);
      
      if (strOperation.equals(LDAPInteractionSpec.LOAD_DATA_FUNCTION))
      {
        loadData();
      }
      else if (strOperation.equals(LDAPInteractionSpec.GET_ELEMENT_FUNCTION))
      {
        String name = (String)((IndexedRecord)input).get(ELEMENT_FIELD);
        EstructuralElement elm = getEstructuralElement( name );
        addOutputValue(input,output,elm);
      }
      else if (strOperation.equals(LDAPInteractionSpec.GET_TOP_ELEMENTS_FUNCTION))
      {
        addOutputValue(input,output,getTopLevelElements());
      }
      else if (strOperation.equals(LDAPInteractionSpec.COLLECT_CAS_FUNCTION))
      {
        addOutputValue(input,output,collectCAs());
      }
      else if (strOperation.equals(LDAPInteractionSpec.GET_LAST_UPDATED_FUNCTION))
      {
        addOutputValue(input,output,getLastUpdated());
      }
      else
      {
        pkiva.log.LogManager.getLogger(this.getClass()).error("Invalid request to execute. Function not supported: " + strOperation);
        throw new ResourceException(INVALID_FUNCTION_ERROR);
      }
    }
    else
    {
      throw new ResourceException(CLOSED_ERROR);
    }
    return true;
  }
  
  public Record execute(InteractionSpec ispec, Record input) throws ResourceException
  {
    throw new NotSupportedException(EXECUTE_WITH_INPUT_RECORD_ONLY_NOT_SUPPORTED);
  }
  
  public ResourceWarning getWarnings() throws ResourceException
  {
    return null;
  }
  public void clearWarnings() throws ResourceException
  {
  }
  
  protected void addOutputValue(Record input, Record output,Object outval) throws ResourceException
  {
    
    if (input.getRecordName().equals(LDAPIndexedRecord.INPUT))
    {
      if (output.getRecordName().equals(LDAPIndexedRecord.OUTPUT))
      {
        ((LDAPIndexedRecord) output).clear();
        // LDAPIndexedRecord is based on ArrayList, so it's suposed to support null values
        ((LDAPIndexedRecord) output).add(outval); 
      } else
      {
        throw new ResourceException(INVALID_OUTPUT_ERROR);
      }
    } else
    {
      throw new ResourceException(INVALID_INPUT_ERROR);
    }
    
    
  }
  
  protected EstructuralElement getEstructuralElement( String name ) throws ResourceException
  {
    try
    {
      return LDAPManager.getInstance().getEstructuralElement( name );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.LDAPManager getEstructuralElement", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in LDAPManager getEstructuralElement." + e.getMessage());
    }
  }
  
  protected Collection getTopLevelElements( ) throws ResourceException
  {
    try
    {
      return LDAPManager.getInstance().getTopLevelElements( );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.LDAPManager getTopLevelElements", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in LDAPManager getTopLevelElements." + e.getMessage());
    }
  }
  
  protected Collection collectCAs( ) throws ResourceException
  {
    try
    {
      return LDAPManager.getInstance().collectCAs( );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.LDAPManager collectCAs", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in LDAPManager collectCAs." + e.getMessage());
    }
  }
  
  protected Date getLastUpdated( ) throws ResourceException
  {
    try
    {
      return LDAPManager.getInstance().getLastUpdated( );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.LDAPManager getLastUpdated", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in LDAPManager getLastUpdated." + e.getMessage());
    }
  }
  
  protected void loadData() throws ResourceException
  {
    try
    {
      LDAPManager.getInstance().loadData( );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.LDAPManager loadData", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in LDAPManager loadData." + e.getMessage());
    }
  }
  
  
}
