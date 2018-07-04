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

import pkiva.validation.ocsp.OCSPManager;
import pkiva.exceptions.CertificateChainRevocationException;

import java.util.Hashtable;
import java.util.Collection;
import java.util.Date;
import java.beans.PropertyChangeSupport;
import java.security.cert.CRLSelector;
import java.security.cert.X509Certificate;
import javax.naming.Name;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NameParser;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.DirContext;
import javax.naming.directory.Attributes;
import javax.resource.ResourceException;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version $Revision: 1.5 $
 */
public class OCSPJBDirContextImpl implements OCSPJBDirContext
{
   OCSPJBManagedConnection mc;

   /** Creates new FSDirContext */
   public OCSPJBDirContextImpl(OCSPJBManagedConnection mc)
   {
      this.mc = mc;
   }

   protected void setManagedConnection(OCSPJBManagedConnection mc)
   {
      this.mc = mc;
   }

   public Attributes getAttributes(Name name, String[] str) throws NamingException
   {
      return null;
   }
   
   public void close() throws NamingException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% LDAPJBDirContextImpl close");
      mc.close();
   }

   public NamingEnumeration list(String str) throws NamingException
   {
      return null;
   }
   
   public void unbind(Name name) throws NamingException
   {
   }
   
   public DirContext getSchemaClassDefinition(Name name) throws NamingException
   {
      return null;
   }
   
   public DirContext createSubcontext(String str, Attributes attributes) throws NamingException
   {
      return null;
   }
   
   public String getNameInNamespace() throws NamingException
   {
      return null;
   }
   
   public Object addToEnvironment(String str, Object obj) throws NamingException
   {
      return null;
   }
   
   public NamingEnumeration listBindings(Name name) throws NamingException
   {
      return null;
   }
   
   public void bind(Name name, Object obj) throws NamingException
   {
   }
   
   public NamingEnumeration search(String str, Attributes attributes, String[] str2) throws NamingException
   {
      return null;
   }
   
   public void modifyAttributes(Name name, int param, Attributes attributes) throws NamingException
   {
   }
   
   public Hashtable getEnvironment() throws NamingException
   {
      return null;
   }
   
   public void bind(String str, Object obj) throws NamingException
   {
   }
   
   public void rebind(String str, Object obj, Attributes attributes) throws NamingException
   {
   }
   
   public DirContext getSchema(Name name) throws NamingException
   {
      return null;
   }
   
   public DirContext getSchemaClassDefinition(String str) throws NamingException
   {
      return null;
   }
   
   public Object lookup(String str) throws NamingException
   {
      return null;
   }
   
   public void destroySubcontext(String str) throws NamingException
   {
   }
   
   public Context createSubcontext(Name name) throws NamingException
   {
      return null;
   }
   
   public Object lookupLink(String str) throws NamingException
   {
      return null;
   }
   
   public DirContext getSchema(String str) throws NamingException
   {
      return null;
   }
   
   public Object lookup(Name name) throws NamingException
   {
      return null;
   }
   
   public void destroySubcontext(Name name) throws NamingException
   {
   }
   
   public NamingEnumeration listBindings(String str) throws NamingException
   {
      return null;
   }
   
   public void rebind(String str, Object obj) throws NamingException
   {
   }
   
   public Object removeFromEnvironment(String str) throws NamingException
   {
      return null;
   }
   
   public void bind(String str, Object obj, Attributes attributes) throws NamingException
   {
   }
   
   public NamingEnumeration search(Name name, Attributes attributes) throws NamingException
   {
      return null;
   }
   
   public NameParser getNameParser(String str) throws NamingException
   {
      return null;
   }
   
   public void bind(Name name, Object obj, Attributes attributes) throws NamingException
   {
   }
   
   public Attributes getAttributes(String str) throws NamingException
   {
      return null;
   }
   
   public void rename(String str, String str1) throws NamingException
   {
   }
   
   public void rename(Name name, Name name1) throws NamingException
   {
   }
   
   public DirContext createSubcontext(Name name, Attributes attributes) throws NamingException
   {
      return null;
   }
   
   public void rebind(Name name, Object obj, Attributes attributes) throws NamingException
   {
   }
   
   public NamingEnumeration list(Name name) throws NamingException
   {
      return null;
   }
   
   public Context createSubcontext(String str) throws NamingException
   {
      return null;
   }
   
   public void modifyAttributes(String str, int param, Attributes attributes) throws NamingException
   {
   }
   
   public NamingEnumeration search(String str, Attributes attributes) throws NamingException
   {
      return null;
   }
   
   public Name composeName(Name name, Name name1) throws NamingException
   {
      return null;
   }
   
   public String composeName(String str, String str1) throws NamingException
   {
      return null;
   }
   
   public NamingEnumeration search(Name name, Attributes attributes, String[] str) throws NamingException
   {
      return null;
   }
   
   public void rebind(Name name, Object obj) throws NamingException
   {
   }
   
   public void modifyAttributes(Name name, ModificationItem[] modificationItem) throws NamingException
   {
   }
   
   public NamingEnumeration search(Name name, String str, SearchControls searchControls) throws NamingException
   {
      return null;
   }
   
   public NamingEnumeration search(Name name, String str, Object[] obj, SearchControls searchControls) throws NamingException
   {
      return null;
   }
   
   public void unbind(String str) throws NamingException
   {
   }
   
   public void modifyAttributes(String str, ModificationItem[] modificationItem) throws NamingException
   {
   }
   
   public Attributes getAttributes(Name name) throws NamingException
   {
      return null;
   }
   
   public Object lookupLink(Name name) throws NamingException
   {
      return null;
   }
   
   public NameParser getNameParser(Name name) throws NamingException
   {
      return null;
   }
   
   public Attributes getAttributes(String str, String[] str1) throws NamingException
   {
      return null;
   }
   
   public NamingEnumeration search(String str, String str1, SearchControls searchControls) throws NamingException
   {
      return null;
   }
   
   public NamingEnumeration search(String str, String str1, Object[] obj, SearchControls searchControls) throws NamingException
   {
      return null;
   }

    // JCA Specific methods:
    public Object execute(String strOperation) throws ResourceException
    {
        return execute(strOperation, null);
    }

    public Object execute(String strOperation, Object params) throws ResourceException
    {

//        pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% Request to execute. Function Name: " + strOperation);

        Object returnObj = null;

        if (strOperation.equals(VALIDATE_FUNCTION))
        {
            returnObj = validate((X509Certificate[]) params);
        }
        else
        {
          pkiva.log.LogManager.getLogger(this.getClass()).error("Invalid request to execute. Function not supported: " + strOperation);
          throw new ResourceException( "Invalid request to execute. Function not supported: " + strOperation);
        }

      return returnObj;
    }

    // PKIVA Specific methods:
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
