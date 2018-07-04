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

import javax.resource.ResourceException;
import javax.resource.spi.ManagedConnectionMetaData;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version 
 */
public class OCSPJBManagedConnectionMetaData implements ManagedConnectionMetaData
{
   /** Creates new FSManagedConnectionMetaData */
    public OCSPJBManagedConnectionMetaData()
    {
    }

    public String getEISProductName() throws ResourceException
    {
       return "Local File System Adaptor";
    }

    public String getEISProductVersion() throws ResourceException
    {
       return "JBoss 2.4.x JCA";
    }

    public int getMaxConnections() throws ResourceException
    {
       return 100;
    }

    public String getUserName() throws ResourceException
    {
       return "nobody";
    }

}
