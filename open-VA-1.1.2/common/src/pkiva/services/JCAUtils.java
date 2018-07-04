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
package pkiva.services;

import pkiva.ldap.connectors.LDAPJBDirContextFactory;
import pkiva.ldap.connectors.LDAPJBDirContext;
import pkiva.validation.connectors.CRLJBDirContext;
import pkiva.validation.connectors.CRLJBDirContextFactory;
import pkiva.validation.ocsp.connectors.OCSPJBDirContextFactory;
import pkiva.validation.ocsp.connectors.OCSPJBDirContext;

import javax.naming.NamingException;
import javax.resource.ResourceException;

public final class JCAUtils
{
    private static final String LDAP_RA_PATH = "connectors/LDAP/ConnectionFactories";
    private static final String CRL_RA_PATH = "connectors/CertValidationChannels/ConnectionFactories/CRL";
    private static final String OCSP_RA_PATH = "connectors/CertValidationChannels/ConnectionFactories/OCSP";

    public static Object executeLDAP_RA_Function(String operation) throws ResourceException {
        return executeLDAP_RA_Function(operation, null);
    }

    public static Object executeLDAP_RA_Function(String operation, Object param) throws ResourceException {
        LDAPJBDirContext ldapjbDirContext = null;
        try {
            LDAPJBDirContextFactory cxFactory = ServiceLocator.getInstance().getLDAPJBDirContextFactory( LDAP_RA_PATH );
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeLDAP_RA_Function::cxFactory::" + cxFactory);

            ldapjbDirContext = cxFactory.getConnection();
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeLDAP_RA_Function::connection::" + ldapjbDirContext);

            return ldapjbDirContext.execute(operation, param);
        } catch (ResourceException e) {
            throw e;
        } catch (Exception e) {
            throw (ResourceException) new ResourceException("Error executing LDAP RA function:" + operation).initCause(e);
        } finally {
            if (ldapjbDirContext != null) {
                try {
                    ldapjbDirContext.close();
                } catch (NamingException e) {
                    pkiva.log.LogManager.getLogger(JCAUtils.class).error("Closing LDAPJBDirContext", e);
                }
            }
        }

    }

    public static Object executeCRL_RA_Function(String operation) throws ResourceException {
        return executeCRL_RA_Function(operation, null);
    }

    public static Object executeCRL_RA_Function(String operation, Object param) throws ResourceException {
        CRLJBDirContext crljbDirContext = null;
        try {
            CRLJBDirContextFactory cxFactory = ServiceLocator.getInstance().getCRLJBDirContextFactory( CRL_RA_PATH );
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeCRL_RA_Function::cxFactory::" + cxFactory);

            crljbDirContext = cxFactory.getConnection();
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeCRL_RA_Function::connection::" + crljbDirContext);

            return crljbDirContext.execute(operation, param);
        } catch (ResourceException e) {
            throw e;
        } catch (Exception e) {
            throw (ResourceException) new ResourceException("Error executing CRL RA function:" + operation).initCause(e);
        } finally {
            if (crljbDirContext != null) {
                try {
                    crljbDirContext.close();
                } catch (NamingException e) {
                    pkiva.log.LogManager.getLogger(JCAUtils.class).error("Closing CRLJBDirContext", e);
                }
            }
        }

    }

    public static Object executeOCSP_RA_Function(String operation) throws ResourceException {
        return executeCRL_RA_Function(operation, null);
    }

    public static Object executeOCSP_RA_Function(String operation, Object param) throws ResourceException {
        OCSPJBDirContext ocspjbDirContext = null;
        try {
            OCSPJBDirContextFactory cxFactory = ServiceLocator.getInstance().getOCSPJBDirContextFactory( OCSP_RA_PATH );
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeOCSP_RA_Function::cxFactory::" + cxFactory);

            ocspjbDirContext = cxFactory.getConnection();
            pkiva.log.LogManager.getLogger(JCAUtils.class).debug("JCAUtils::executeOCSP_RA_Function::connection::" + ocspjbDirContext);

            return ocspjbDirContext.execute(operation, param);
        } catch (ResourceException e) {
            throw e;
        } catch (Exception e) {
            throw (ResourceException) new ResourceException("Error executing OCSP RA function:" + operation).initCause(e);
        } finally {
            if (ocspjbDirContext != null) {
                try {
                    ocspjbDirContext.close();
                } catch (NamingException e) {
                    pkiva.log.LogManager.getLogger(JCAUtils.class).error("Closing OCSPJBDirContext", e);
                }
            }
        }

    }
}
