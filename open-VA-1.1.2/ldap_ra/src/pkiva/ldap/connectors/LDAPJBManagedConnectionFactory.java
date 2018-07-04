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

import java.io.File;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Set;
import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionFactory;
import javax.security.auth.Subject;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version $Revision: 1.5 $
 */
public class LDAPJBManagedConnectionFactory 
    implements ManagedConnectionFactory, 
               Serializable
{
//    static Category log = Category.getInstance(LDAPJBManagedConnectionFactory.class);

    /** Creates new FSManagedConnectionFactory */
    public LDAPJBManagedConnectionFactory()
    {
    }
    
    public Object createConnectionFactory()
        throws ResourceException
    {
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% createConnectionFactory");
        throw new UnsupportedOperationException("Cannot be used in unmanaged env");
    }

    public Object createConnectionFactory(ConnectionManager cm)
        throws ResourceException
    {
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% createConnectionFactory, cm=" + cm);
        LDAPJBRequestInfo fsInfo = new LDAPJBRequestInfo();
        return new LDAPJBDirContextFactoryImpl(cm, this, fsInfo);
    }

    public ManagedConnection createManagedConnection(Subject subject,
                                                     ConnectionRequestInfo info)
        throws ResourceException
    {
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% createManagedConnection, subject=" + subject + ", info=" + info);
        LDAPJBRequestInfo fsInfo = (LDAPJBRequestInfo) info;
        return new LDAPJBManagedConnection(subject, fsInfo);
    }

    public ManagedConnection matchManagedConnections(Set connectionSet, 
                                                     Subject subject,
                                                     ConnectionRequestInfo info)
        throws ResourceException
    {
//        pkiva.log.LogManager.getLogger(this.getClass()).debug("#### %%%% matchManagedConnections, connectionSet=" + connectionSet + ", subject=" + subject  +", info="  +info);
        return (ManagedConnection) connectionSet.iterator().next();
    }
    
    public PrintWriter getLogWriter() 
        throws ResourceException
    {
        return null;
    }
    

    public void setLogWriter(PrintWriter out) 
        throws ResourceException
    {
    }

    public boolean equals(Object other)
    {
        return super.equals(other);
    }

    public int hashCode()
    {
        return super.hashCode();
    }
    
}
