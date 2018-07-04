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

import java.io.Serializable;
import pkiva.exceptions.*;
import java.security.cert.*;
import java.util.*;
import pkiva.exceptions.ValidationPolicyNotAvailableException;
import javax.resource.cci.*;
import javax.naming.InitialContext;
import javax.resource.spi.*;
import pkiva.validation.connectors.*;
import pkiva.services.*;

public class CertValidationChannel {
	private static final String CONFIGPATH="connectors/CertValidationChannels/";
	private static final String CONNFACTORIES="ConnectionFactories/";
	private static final String INTERACTIONS="InteractionSpecs/";
	private static final String INPUT = "input";
	private static final String OUTPUT = "output";
        private static final short CHANNEL_CRL_ID=1;
        private static final short CHANNEL_OCSP_ID=2;
        private static final short CHANNEL_SOAP_ID=4;
        private static final String CHANNEL_CRL_SUFFIX="CRL";
        private static final String CHANNEL_OCSP_SUFFIX="OCSP";
        private static final String CHANNEL_SOAP_SUFFIX="SOAP";
        public static final int CERTIFICATE_FIELD = 0;
	public static final int RESULT_FIELD = 0;
	private int m_channels=0;
        private String m_ChannelsConnector="OR";
	
        public CertValidationChannel(short channels) {m_channels=channels;}
	
	/*public boolean isRevoked(X509Certificate cert) throws CertificateValidationErrorException, ValidationPolicyNotAvailableException{
	    pkiva.log.LogManager.getLogger(this.getClass()).debug("CertValidationChannel.isRevoked(). Parameters: cert=" + (cert!=null?cert.getSubjectDN():null));
	    try{
		int lchannels=0;
		if(m_channels==0)
			lchannels=determineChannel(cert);
		else{
                        if(isValidChannel(cert))
                            lchannels=m_channels;
                        else
                            throw new ValidationPolicyNotAvailableException("El metodo de validacion no es válido para el certificado");
                }
                pkiva.log.LogManager.getLogger(this.getClass()).debug("CertValidationChannel.isRevoked(). Channels:" + lchannels);
                short idmask=1;
                boolean lisRevoked=false;
                boolean isRevoked=false;
                do{
                    int channelID=lchannels & idmask;
                    if (channelID!=0){
	                    String channelSuffix=IDToSuffix(channelID);

						// ServiceLocator. ...

        	            InitialContext context = new InitialContext();
                	    ConnectionFactory cxFactory = (ConnectionFactory) context.lookup(CONFIGPATH + CONNFACTORIES + channelSuffix);


	                    RecordFactory recordFactory = cxFactory.getRecordFactory();
        	            IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
                	    input.clear();
	                    input.add(cert);
        	            IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
	                    //InteractionSpec ispec = (InteractionSpec) context.lookup(CONFIGPATH + INTERACTIONS + channelSuffix);
        	            CertValidationChannelInteractionSpec ispec =new CertValidationChannelInteractionSpecImpl();
	                    ispec.setFunctionName(CertValidationChannelInteractionSpec.IS_REVOKED_FUNCTION);
        	            Connection connection = cxFactory.getConnection();  
			    pkiva.log.LogManager.getLogger(this.getClass()).debug("CertValidationChannel.isRevoked(). Conecto al resource adapter:" + CONFIGPATH + CONNFACTORIES + channelSuffix);
                	    Interaction interaction = connection.createInteraction();
	                    interaction.execute(ispec, input, output);
        	            isRevoked = ((Boolean) output.get(RESULT_FIELD)).booleanValue();
                	    pkiva.log.LogManager.getLogger(this.getClass()).debug("CRLManager.isRevoked(). El RA devolvió Revoked=" + isRevoked );
                	    interaction.close();
	                    connection.close();
	                    if (isRevoked)
	                    	lisRevoked=true;
        	            //if(isRevoked && (m_ChannelsConnector.equals("AND"))) return false;
	       	      }
	       	      idmask<<=1;
                }while ((idmask>0) && m_ChannelsConnector.equals("AND"));
            	
            	pkiva.log.LogManager.getLogger(this.getClass()).debug("CRLManager.isRevoked(). Saliendo del método. El resultado final es lisRevoked= " + lisRevoked);
                return lisRevoked;
            }catch(ValidationPolicyNotAvailableException e){
                throw e;
            }catch(Exception e){
   	    	throw new CertificateValidationErrorException(e.getMessage());
   	    }
	}*/
	
 /*   public Collection getCRLs ( CRLSelector sel ) throws CertificateValidationErrorException
    {
        try
        {
            // determine channel if needed ...
           String channelSuffix=CHANNEL_CRL_SUFFIX;

//           InitialContext context = new InitialContext();
//           ConnectionFactory cxFactory = (ConnectionFactory) context.lookup(CONFIGPATH + CONNFACTORIES + channelSuffix);
           ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES + channelSuffix);



           RecordFactory recordFactory = cxFactory.getRecordFactory();
           IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
           input.clear();   
           input.add(sel);

           IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);

           //InteractionSpec ispec = (InteractionSpec) context.lookup(CONFIGPATH + INTERACTIONS + channelSuffix);
           CertValidationChannelInteractionSpec ispec =new CertValidationChannelInteractionSpecImpl();
           ispec.setFunctionName(CertValidationChannelInteractionSpec.GET_CRLS_FUNCTION);

           Connection connection = cxFactory.getConnection();  
           Interaction interaction = connection.createInteraction();
           interaction.execute(ispec, input, output);

           Collection col = (Collection) output.get(RESULT_FIELD);

           interaction.close();
           connection.close();

           return col;
        }
        catch(Exception e)
        {
            // TODO: CHANGE exception management
            throw new CertificateValidationErrorException(e.getMessage());
   	    }
    }*/
    
        private boolean isValidChannel(X509Certificate cert) throws ValidationPolicyNotAvailableException {
            
            ValidationPolicyDefinitionsStore vpds= ValidationPolicyDefinitionsStore.getInstance();
            String policy=vpds.getPolicyForCertificate(cert);
            
            short idmask=1;
           // assert(m_channels!=0);
            //Primero debe verificar que TODOS los channels indicados (si se indicó alguno)
            //Esten aceptados por la politica correspondiente al certificado
            do{
               idmask<<=1;
               if (!(policy.indexOf(IDToSuffix( m_channels & idmask))>0))       
                  return false;
            }while ((idmask>0) && m_ChannelsConnector.equals("AND"));
            
            //Si todos los channels indicados son aceptados, debe verificar que si el 
            //operador de la policy es un AND, todos los elementos que aparezcan en esa
            //policy deben estar en m_channels
            if (policy.indexOf(" AND ")>0){
               String[] m_channelsArray=policy.split(" AND ");
               for(int i=0;i<m_channelsArray.length;i++){
                   if((suffixToID(m_channelsArray[i].trim()) & m_channels)==0)
                       return false;
                }
               return true;
            }
            return true;
        }
        
	private int determineChannel(X509Certificate cert) throws ValidationPolicyNotAvailableException {
            ValidationPolicyDefinitionsStore vpds=ValidationPolicyDefinitionsStore.getInstance();
            String policy=vpds.getPolicyForCertificate(cert);	
            int ret=0;
            int channels=0;
            if (policy.indexOf(" AND ")>0){
               String[] m_channelsArray=policy.split(" AND ");
               for(int i=0;i<m_channelsArray.length;i++)
                   channels&=suffixToID(m_channelsArray[i].trim());
            }else{
               String[] m_channelsArray=policy.split(" OR ");
               ret=suffixToID(m_channelsArray[0]);
            }
            return ret;
	}
        
        private String IDToSuffix(int channelID) throws ValidationPolicyNotAvailableException{
            String res=null;
            switch(channelID){
                case CHANNEL_CRL_ID:
                    res=CHANNEL_CRL_SUFFIX;
                    break;
                case CHANNEL_OCSP_ID:
                    res=CHANNEL_OCSP_SUFFIX;
                    break;
                case CHANNEL_SOAP_ID:
                    res=CHANNEL_SOAP_SUFFIX;
                    break;
                default:
                    throw new ValidationPolicyNotAvailableException("El metodo de validacion no existe");
            }
            return res;
        }
        
        private short suffixToID(String suffix) throws ValidationPolicyNotAvailableException{
            
            if(suffix.equals(CHANNEL_CRL_SUFFIX))
                return CHANNEL_CRL_ID;
            
            if(suffix.equals(CHANNEL_OCSP_SUFFIX))
                return CHANNEL_OCSP_ID;
            
            if(suffix.equals(CHANNEL_SOAP_SUFFIX))
                return CHANNEL_SOAP_ID;
            
            throw new ValidationPolicyNotAvailableException("El metodo de validacion no existe");

        }
}

