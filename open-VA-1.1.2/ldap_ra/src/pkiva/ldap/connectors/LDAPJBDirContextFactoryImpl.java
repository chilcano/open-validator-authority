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

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.DirContext;
import javax.naming.Reference;
import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ManagedConnectionFactory;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version $Revision: 1.5 $
 */
public class LDAPJBDirContextFactoryImpl implements LDAPJBDirContextFactory
{
   private transient ConnectionManager manager;
   private transient ManagedConnectionFactory factory;
   private transient LDAPJBRequestInfo fsInfo;
   private Reference reference;

   LDAPJBDirContextFactoryImpl(ConnectionManager manager,
      ManagedConnectionFactory factory, LDAPJBRequestInfo fsInfo)
   {
      this.manager = manager;
      this.factory = factory;
      this.fsInfo = fsInfo;
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% ctor, fsInfo="+fsInfo);
   }

   public LDAPJBDirContext getConnection() throws NamingException
   {
      //log.debug("getConnection", new Exception("CalledBy:"));
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getConnection");
      LDAPJBDirContext dc = null;
      try
      {
         dc = (LDAPJBDirContext) manager.allocateConnection(factory, fsInfo);
      }
      catch(ResourceException e)
      {
         throw new NamingException("Unable to get Connection: "+e);
      }
      return dc;
   }
   public void setReference(Reference reference)
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% setReference, reference="+reference);
      this.reference = reference;
   }

   public Reference getReference() throws NamingException
   {
//      pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% getReference");
      return reference;
   }
}
