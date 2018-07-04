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
package pkiva.validation;

import java.util.*;
//import java.security.*;
import java.security.cert.*;
import javax.resource.cci.*;
import javax.resource.ResourceException;

import pkiva.validation.ocsp.*;
import pkiva.validation.ocsp.connectors.*;
import pkiva.services.*;

/**
 * DPCertPathChecker is a <code>PKIXCertPathChecker</code> that checks
 * revocation status information on a PKIX certificate using DPs
 *
 */
public class OCSPCertPathChecker extends GenericPKIXCertPathChecker {
    protected Vector v = null;
    /**
     * Default Constructor.
     */
    public OCSPCertPathChecker() {  }
    
    /**
     * Initializes the internal state of the checker from parameters
     * specified in the constructor
     */
    public void init(boolean forward) throws CertPathValidatorException {
        if (forward)
        throw new CertPathValidatorException("forward checking "
        + "not supported");
        v = new Vector();
    }
    
    public boolean isForwardCheckingSupported() {
        return false;
    }
    
    public Set getSupportedExtensions() {
        return null;
    }
    
    public Object clone(){
    	return this;
    }
    
    public ValidationObject checkWithResponse(Certificate cert, Collection unresolvedCritExts) throws CertPathValidatorException 
    {
// diriarte: check !!
//Checking chain result: INVALID_CERTCHAIN due to exception: java.security.cert.CertPathValidatorException: unrecognized critical extension(s)
        unresolvedCritExts.clear();

        pkiva.log.LogManager.getLogger(this.getClass()).debug("Storing certificate #"+v.size()+". SN="+((X509Certificate)cert).getSerialNumber());        
        v.add(cert);
        if(!CertUtils.isEndEntity((X509Certificate)cert))
            return null;//Noyhing else to do.
        //Now, we have the full chain.

        pkiva.log.LogManager.getLogger(this.getClass()).debug("Certificate chain is finished with "+v.size()+" elements. Processing.");
        
        // TODO: What to do with the stored chain

        // v(0) = firstCA, v(n-1) = endEntity
        //java.util.Collections.reverse(v);//If needed ...
        X509Certificate[] chain = (X509Certificate[]) v.toArray ( new X509Certificate[0] );
        OCSPValidationResponse resp = doOCSPValidation ( chain );
        checkResponse ( resp );
        OCSPValidationInfo info = resp.getInfo( );

        return info;
    }

  protected OCSPValidationResponse doOCSPValidation ( X509Certificate[] chain ) throws CertPathValidatorException 
  {
    OCSPValidationResponse res = null;

//    Connection connection=null;
//    Interaction interaction=null;
//
      try {
//       String CONNECTION_PATH="connectors/CertValidationChannels/ConnectionFactories/OCSP";
//       String INPUT = "input";
//       String OUTPUT = "output";
//
//       ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONNECTION_PATH);
//
//       RecordFactory recordFactory = cxFactory.getRecordFactory();
//       IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//       input.clear();
//       input.add(chain);
//
//       IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//
//       OCSPInteractionSpec ispec =new OCSPInteractionSpecImpl();
//       ispec.setFunctionName(OCSPInteractionSpec.VALIDATE_FUNCTION);
//
//       connection = cxFactory.getConnection();
//       interaction = connection.createInteraction();
//       interaction.execute(ispec, input, output);
//
//       res = (OCSPValidationResponse) output.get(0);
//       return res;

          return (OCSPValidationResponse) JCAUtils.executeOCSP_RA_Function(OCSPJBDirContext.VALIDATE_FUNCTION, chain);
    }
    catch(ResourceException e){
        pkiva.log.LogManager.getLogger(this.getClass()).error("Unexpected error in OCSP validation",e);
        throw new CertPathValidatorException("Unexpected error in OCSP validation",e);
    }
//    finally
//    {
//        try{
//            if(interaction!=null)
//                interaction.close();
//        }
//        catch(javax.resource.ResourceException re){}
//        try{
//            if(connection!=null)
//                connection.close();
//        }
//        catch(javax.resource.ResourceException re){}
//    }

  }
    
  protected void checkResponse ( OCSPValidationResponse res ) throws CertPathValidatorException 
  {
    try
    {
      if ( res.getState() != OCSPValidationResponse.OK )
      {
        Throwable cause = res.getCause ();
        if ( cause != null )
          throw cause;
        else
          throw new CertPathValidatorException ( "Unknown cause error parsing OCSP validation response with state:" + res.getState());
      }
    }
    catch ( CertPathValidatorException e )
    {
      throw e;
    }
    catch ( Throwable t )
    {
      throw new CertPathValidatorException ( "Unexpected error parsing OCSP validation response", t );
    }

  }

}
