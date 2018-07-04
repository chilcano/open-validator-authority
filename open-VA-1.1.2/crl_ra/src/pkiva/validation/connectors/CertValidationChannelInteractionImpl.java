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

import pkiva.validation.crl.*;

abstract public class CertValidationChannelInteractionImpl implements Interaction
{
  //protected static String CHANNELSTR="";
  //private static final int CERTIFICATE_FIELD = 0;
  private static final int SELECTOR_FIELD = 0;
  private static final String CLOSED_ERROR = "Connection closed";
  private static final String INVALID_FUNCTION_ERROR = "Invalid function";
  private static final String INVALID_INPUT_ERROR = "Invalid input record for function";
  private static final String INVALID_OUTPUT_ERROR = "Invalid output record for function";
  private static final String EXECUTE_WITH_INPUT_RECORD_ONLY_NOT_SUPPORTED = "execute() with input record only not supported";
  
  private Connection connection;
  private boolean valid;
  
  public CertValidationChannelInteractionImpl(Connection connection)
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
  
    /*public boolean execute(InteractionSpec ispec, Record input, Record output) throws ResourceException {
     
       if (valid) {
        String strOperation="";
           try{
           java.lang.reflect.Method m=ispec.getClass().getMethod("getFunctionName",new Class[0]);
           strOperation=(String)m.invoke(ispec,new Object[0]);
        }catch(Exception e){
            throw new ResourceException("Exception in resource adapter when invoking getFunctionName");
        }
     
        boolean bReturn=false;
        boolean isValidFunction=false;
     
        if (strOperation.equals(CertValidationChannelInteractionSpec.IS_REVOKED_FUNCTION)) {
            isValidFunction=true;
            X509Certificate cert=(X509Certificate)((CertValidationChannelIndexedRecord)input).get(CERTIFICATE_FIELD);
            bReturn=!validateCertificate(cert);
        }
        if (isValidFunction)
           addOutputValue(input,output,new Boolean(bReturn));
        else
           throw new ResourceException(INVALID_FUNCTION_ERROR);
      } else {
            throw new ResourceException(CLOSED_ERROR);
        }
        return true;
    }*/
  
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
      // javax.resource.ResourceException does not support chained Exceptions
        throw new ResourceException("Exception in resource adapter when invoking getFunctionName:" + e.getMessage());
      }
      
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Request to execute. Function Name: " + strOperation);
      
      if (strOperation.equals(CertValidationChannelInteractionSpec.GET_CRLS_FUNCTION))
      {
        CRLSelector sel = (CRLSelector)((IndexedRecord)input).get(SELECTOR_FIELD);
        CRLValidationResponse resp = getCRLs( sel );
        addOutputValue(input,output,resp);
      }
      /*else if (strOperation.equals(CertValidationChannelInteractionSpec.INIT_FUNCTION))
      {
        // TODO: call 2 init function
        //addOutputValue(input,output, null);
      }*/
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
    
    if (input.getRecordName().equals(CertValidationChannelIndexedRecord.INPUT))
    {
      if (output.getRecordName().equals(CertValidationChannelIndexedRecord.OUTPUT))
      {
        ((CertValidationChannelIndexedRecord) output).clear();
        ((CertValidationChannelIndexedRecord) output).add(outval);
      } else
      {
        throw new ResourceException(INVALID_OUTPUT_ERROR);
      }
    } else
    {
      throw new ResourceException(INVALID_INPUT_ERROR);
    }
    
    
  }
  
  //abstract protected boolean validateCertificate(X509Certificate Certificate)  throws ResourceException;
  
  abstract protected CRLValidationResponse getCRLs(CRLSelector sel) throws ResourceException;
  
  //abstract protected void init( ) throws ResourceException;
  
  
}
