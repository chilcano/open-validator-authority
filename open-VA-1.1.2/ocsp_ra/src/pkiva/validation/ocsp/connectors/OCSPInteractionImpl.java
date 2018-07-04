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

import pkiva.validation.ocsp.*;
import pkiva.exceptions.*;


public class OCSPInteractionImpl implements Interaction
{
  public static final int CHAIN_FIELD = 0;
  private static final String CLOSED_ERROR = "Connection closed";
  private static final String INVALID_FUNCTION_ERROR = "Invalid function";
  private static final String INVALID_INPUT_ERROR = "Invalid input record for function";
  private static final String INVALID_OUTPUT_ERROR = "Invalid output record for function";
  private static final String EXECUTE_WITH_INPUT_RECORD_ONLY_NOT_SUPPORTED = "execute() with input record only not supported";
  
  private Connection connection;
  private boolean valid;
  
  public OCSPInteractionImpl(Connection connection)
  {
    super();
    this.connection = connection;
    valid = true;
  }
  
  public void close() throws ResourceException
  {
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
      
      if (strOperation.equals(OCSPInteractionSpec.VALIDATE_FUNCTION))
      {
        X509Certificate[] chain = (X509Certificate[])((IndexedRecord)input).get(CHAIN_FIELD);
        OCSPValidationResponse resp = validate(chain);
        addOutputValue(input,output,resp);
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
    
    if (input.getRecordName().equals(OCSPIndexedRecord.INPUT))
    {
      if (output.getRecordName().equals(OCSPIndexedRecord.OUTPUT))
      {
        ((OCSPIndexedRecord) output).clear();
        // OCSPIndexedRecord is based on ArrayList, so it's suposed to support null values
        ((OCSPIndexedRecord) output).add(outval); 
      } else
      {
        throw new ResourceException(INVALID_OUTPUT_ERROR);
      }
    } else
    {
      throw new ResourceException(INVALID_INPUT_ERROR);
    }
    
    
  }
  
  protected OCSPValidationResponse validate( X509Certificate[] chain )
  {
    OCSPValidationResponse resp;

    try
    {
      resp = OCSPManager.instance().validate( chain );
    }
    catch ( CertificateChainRevocationException e )
    {
      resp = new OCSPValidationResponse( OCSPValidationResponse.REVOKED );
      resp.setCause ( e );
    }
    catch(Throwable t)
    {
      resp = new OCSPValidationResponse( OCSPValidationResponse.ERROR );
      resp.setCause ( t );
    }

    return resp;
  }
  
}
