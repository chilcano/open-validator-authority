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
package pkiva.providers.jce.certstore;

import java.security.cert.*;
import java.security.InvalidAlgorithmParameterException;
import java.util.*;
import java.io.*;
import pkiva.services.*;
import javax.resource.cci.*;
import pkiva.validation.connectors.*;
import pkiva.providers.*;
import pkiva.exceptions.*;

public class RACertStoreSpi extends CertStoreSpi {
    private static final String CONFIGPATH="connectors/CertValidationChannels/";
    private static final String CONNFACTORIES="ConnectionFactories/";
    private static final String CHANNEL_CRL_SUFFIX="CRL";
    private static final String INPUT = "input";
    private static final String OUTPUT = "output";
    public static final int RESULT_FIELD = 0;
    private CollectionCertStoreParameters params;
    public RACertStoreSpi(CertStoreParameters params) throws InvalidAlgorithmParameterException{
        super(params);
    }
    public synchronized  Collection engineGetCertificates(CertSelector selector) throws CertStoreException{
        Collection col = CertStoreProvider.getCAs();
        Vector toReturn = new Vector();
        for(Iterator it = col.iterator();it.hasNext();){
            Certificate c = (Certificate)it.next();
            if(selector.match(c))
                toReturn.add(c);
        }
        return toReturn;
        //throw new CertStoreException("Not Implemented, this CertStore is unically for querying CRLs");
    }
    
    public synchronized Collection engineGetCRLs(CRLSelector sel) throws CertStoreException{
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Retrieving CRL's");
//        Connection connection=null;
//        Interaction interaction=null;
        try{
//            // determine channel if needed ...
//            String channelSuffix=CHANNEL_CRL_SUFFIX;
//
//            ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES + channelSuffix);
//
//            RecordFactory recordFactory = cxFactory.getRecordFactory();
//            IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//            input.clear();
//            input.add(sel);
//
//            IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//
//            //InteractionSpec ispec = (InteractionSpec) context.lookup(CONFIGPATH + INTERACTIONS + channelSuffix);
//            CertValidationChannelInteractionSpec ispec =new CertValidationChannelInteractionSpecImpl();
//            ispec.setFunctionName(CertValidationChannelInteractionSpec.GET_CRLS_FUNCTION);
//
//            connection = cxFactory.getConnection();
//            interaction = connection.createInteraction();
//            interaction.execute(ispec, input, output);
//
////            Collection col = (Collection) output.get(RESULT_FIELD);
//            CRLValidationResponse resp = (CRLValidationResponse) output.get(RESULT_FIELD);

            CRLValidationResponse resp = (CRLValidationResponse) JCAUtils.executeCRL_RA_Function(CRLJBDirContext.GET_CRLS_FUNCTION, sel);
            Collection col = resp.getCrlCollection();
            if ( col == null )
            {
              CRLValidationException crlve = resp.getError();
              throw crlve;
            }
            else if ( col.size() == 0 )
            {
              throw new UnknownCertificateChainRevocationStatusException ( "No CRLs found for certificate" );
            }
            
            pkiva.log.LogManager.getLogger(this.getClass()).info("Returning "+col.size()+" CRL's");
            return col;
        }
        catch(CRLValidationException e){
            //pkiva.log.LogManager.getLogger(this.getClass()).error(e.toString());
            throw new CertStoreException(e);
        }
        catch(UnknownCertificateChainRevocationStatusException e){
            //pkiva.log.LogManager.getLogger(this.getClass()).error(e.toString());
            throw new CertStoreException(e);
        }
        catch(Exception e){
            pkiva.log.LogManager.getLogger(this.getClass()).error("Communication error retrieving CRL's:" + e);
            CRLValidationException crlve = new CRLValidationException ( e.getMessage(), e );
            throw new CertStoreException("Communication error retrieving CRL's:", crlve);
        }
//        finally{
//            try{
//                if(interaction!=null)
//                    interaction.close();
//            }
//            catch(javax.resource.ResourceException re){}
//            try{
//                if(connection!=null)
//                    connection.close();
//            }
//            catch(javax.resource.ResourceException re){}
//        }
    }
}
