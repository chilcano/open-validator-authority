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

import java.io.File;
import javax.resource.spi.ConnectionRequestInfo;

/**
 *
 * @author  Scott.Stark@jboss.org
 * @version $Revision: 1.5 $
 */
public class CRLJBRequestInfo implements ConnectionRequestInfo
{
   /** Creates new FSRequestInfo */
   public CRLJBRequestInfo()
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
