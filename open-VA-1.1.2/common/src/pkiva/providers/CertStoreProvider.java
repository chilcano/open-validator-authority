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
package pkiva.providers;

import java.util.HashSet;
import java.util.Set;
import java.io.*;
import java.security.cert.*;
import javax.resource.spi.*;
import javax.resource.cci.*;
import java.util.*;
import pkiva.ldap.*;
import pkiva.ldap.connectors.*;
import pkiva.services.*;


/** Provides a concrete implementation facade to encapsulate how the PKIVA
 * obtains TrustAnchors, that is, the out-of-the-band trusted CA certificates
 * and completes certificate chains.
 * We do not use the concrete capabilities of getting ARLs or CRLs
 */
public class CertStoreProvider {
    public static final String CONFIGPATH="connectors/LDAP/";
    public static final String CONNFACTORIES="ConnectionFactories";
    public static final String INTERACTIONS="InteractionSpecs/";
    public static final String INPUT = "input";
    public static final String OUTPUT = "output";
    public static final int RESULT_FIELD=0;
    
    
    protected static Set trustAnchorsToReturn=null;
    protected static Date trustAnchorsToReturnDate=null;
    protected static HashSet CAsToReturn=null;
    
    /**
     * Retrieves the TrustAnchors.
     * @return A Set of all the trustAnchors (every element is a
     * <code>java.security.cert.TrustAnchor</code>, or an empty Set if something
     * fails while obtaining them.
     */
    public static Set getTrustAnchors() {
        pkiva.log.LogManager.getLogger(CertStoreProvider.class).debug("Retrieving TrustAnchors. ");
        Date d = getTrustAnchorsDate();      
        if( trustAnchorsToReturnDate==null )
            trustAnchorsToReturn=null;
        else if( !trustAnchorsToReturnDate.equals(d) )
            trustAnchorsToReturn=null;
        trustAnchorsToReturnDate=d;
        
        if(trustAnchorsToReturn!=null){
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).info("Returning "+trustAnchorsToReturn.size()+" cached TrustAnchors. ");
            return trustAnchorsToReturn;
        }

//        Connection connection=null;
//        Interaction interaction=null;
        try{
//            ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES );
//            RecordFactory recordFactory = cxFactory.getRecordFactory();
//            IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//            LDAPInteractionSpec ispec =new LDAPInteractionSpecImpl();
//            ispec.setFunctionName(LDAPInteractionSpec.GET_TOP_ELEMENTS_FUNCTION);
//            IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//            input.clear();
//
//            connection = cxFactory.getConnection();
//            interaction = connection.createInteraction();
//            interaction.execute(ispec, input, output);
//
//            Collection col = (Collection) output.get(RESULT_FIELD);
//
            Collection col = (Collection) JCAUtils.executeLDAP_RA_Function(LDAPJBDirContext.GET_TOP_ELEMENTS_FUNCTION);

            HashSet h = new HashSet(col.size());
            for(Iterator it = col.iterator();it.hasNext();){
                EstructuralElement elm = (EstructuralElement) it.next();
                Collection c = getTrustAnchorsFromEstructuralElement(elm);
                h.addAll(c);
            }
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).info("Returning "+h.size()+" TrustAnchors. ");
            return trustAnchorsToReturn=h;
        }
        catch (javax.resource.ResourceException re){
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving TrustAnchors.",re);
        }
//        catch (pkiva.exceptions.ServiceLocatorException sle){
//            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving TrustAnchors.",sle);
//        }
//        finally{
//            try{
//                if(interaction!=null)
//                    interaction.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing interaction.",re);
//            }
//            try{
//                if(connection!=null)
//                    connection.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing connection.",re);
//            }
//        }
        return Collections.EMPTY_SET;
    }
    
    protected static Date getTrustAnchorsDate(){
//        Connection connection=null;
//        Interaction interaction=null;
        try{
//            ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES );
//            RecordFactory recordFactory = cxFactory.getRecordFactory();
//            IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//            LDAPInteractionSpec ispec =new LDAPInteractionSpecImpl();
//            ispec.setFunctionName(LDAPInteractionSpec.GET_LAST_UPDATED_FUNCTION);
//            IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//            input.clear();
//
//            connection = cxFactory.getConnection();
//            interaction = connection.createInteraction();
//            interaction.execute(ispec, input, output);
//
//            Date d = (Date) output.get(RESULT_FIELD);

            Date d = (Date) JCAUtils.executeLDAP_RA_Function(LDAPJBDirContext.GET_LAST_UPDATED_FUNCTION);
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).debug("Obtained LDAP date for last update: "+d);
            return (d!=null)?d:new Date();
        }
        catch (javax.resource.ResourceException re){
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving TrustAnchors.",re);
        }
//        catch (pkiva.exceptions.ServiceLocatorException sle){
//            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving TrustAnchors.",sle);
//        }
//        finally{
//            try{
//                if(interaction!=null)
//                    interaction.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing interaction.",re);
//            }
//            try{
//                if(connection!=null)
//                    connection.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing connection.",re);
//            }
//        }
        return new Date();
    }
    
    /**
     * Retrieves the CA's.
     * @return A Set of all the ca's (every element is a
     * <code>java.security.cert.X509Certificate</code>, or an empty Set if something
     * fails while obtaining them.
     */
    public static Set getCAs() {
        pkiva.log.LogManager.getLogger(CertStoreProvider.class).debug("Retrieving CA's. ");
        HashSet h = null;
        if(CAsToReturn!=null)
            h=CAsToReturn;
        else{
            Set s = getCAEstructuralElements();
            h = new HashSet(s.size());
            for(Iterator it=s.iterator();it.hasNext();){
                EstructuralElement elm = (EstructuralElement) it.next();
                h.add(elm.getCACertificate());
            }
        }
        pkiva.log.LogManager.getLogger(CertStoreProvider.class).info("Returning "+h.size()+" CA's. ");
        return h;
    }
    
    /**
     * Retrieves the CA's.
     * @return A Set of all the ca's (every element is a EstructuralElement, or
     * an empty Set if something fails while obtaining them.
     */
    public static Set getCAEstructuralElements(){
//        Connection connection=null;
//        Interaction interaction=null;
        try{
//            ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES );
//            RecordFactory recordFactory = cxFactory.getRecordFactory();
//            IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//            LDAPInteractionSpec ispec =new LDAPInteractionSpecImpl();
//            ispec.setFunctionName(LDAPInteractionSpec.COLLECT_CAS_FUNCTION);
//            IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//            input.clear();
//
//            connection = cxFactory.getConnection();
//            interaction = connection.createInteraction();
//            interaction.execute(ispec, input, output);
//
//            Collection col = (Collection) output.get(RESULT_FIELD);

            Collection col = (Collection) JCAUtils.executeLDAP_RA_Function(LDAPJBDirContext.COLLECT_CAS_FUNCTION);
            HashSet h = new HashSet(col.size());
            //pkiva.log.LogManager.getLogger(CertStoreProvider.class).debug("Retrieving CA's.Collection:" + col);
            for(Iterator it = col.iterator();it.hasNext();){
                Object obj= it.next();
                //pkiva.log.LogManager.getLogger(CertStoreProvider.class).debug("Retrieving CA's.Collection Item:" + obj);
                EstructuralElement elm = (EstructuralElement) obj;
                X509Certificate cert = elm.getCACertificate();
                if(cert!=null)
                    h.add(elm);
            }
            return h;
        }
        catch (javax.resource.ResourceException re){
            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving CA's.",re);
        }
//        catch (pkiva.exceptions.ServiceLocatorException sle){
//            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving CA's.",sle);
//        }
//        catch (Throwable t){
//            pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception retrieving CA's.",t);
//        }
//        finally{
//            try{
//                if(interaction!=null)
//                    interaction.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing interaction.",re);
//            }
//            try{
//                if(connection!=null)
//                    connection.close();
//            }
//            catch(javax.resource.ResourceException re){
//                pkiva.log.LogManager.getLogger(CertStoreProvider.class).error("Exception closing connection.",re);
//            }
//        }
        return Collections.EMPTY_SET;
    }
    
    /**
     * Recursive method to retrieve all TrustAnchors hanging from given element.
     * @return A Collection whose elements are TrustAnchors.
     */
    protected static Collection getTrustAnchorsFromEstructuralElement(EstructuralElement elm){
        ArrayList aList = new ArrayList();
        
        X509Certificate ownCert = elm.getCACertificate();
        if( ownCert != null && isTrustAnchor(ownCert))
            aList.add(new TrustAnchor(ownCert,null));
        else if (ownCert == null)
            for(Iterator it = elm.collectCAs(false).iterator();it.hasNext();){
                EstructuralElement el = (EstructuralElement)it.next();
                X509Certificate cert = el.getCACertificate();
                if( cert == null )
                    aList.addAll(getTrustAnchorsFromEstructuralElement(el));
                else if( isTrustAnchor(cert))
                    aList.add(new TrustAnchor(cert,null));
            }
        return aList;
    }
    
    /**
     * Checks if given certificate is a TrustAnchor
     * @param cert The certificate to check
     * @return true if it is a TurstAnchor, false otherwise
     */
    protected static boolean isTrustAnchor(X509Certificate cert){
        return ( cert.getBasicConstraints() >-1 &&
        cert.getIssuerDN().equals( cert.getSubjectDN() )
        );
    }
}
