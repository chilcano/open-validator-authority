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

import pkiva.validation.crl.*;
import java.util.*;
import java.security.cert.*;
import javax.resource.NotSupportedException;
import javax.resource.ResourceException;
import javax.resource.cci.Connection;
import javax.resource.cci.Interaction;
import javax.resource.cci.InteractionSpec;
import javax.resource.cci.Record;
import javax.resource.cci.ResourceWarning;

public class CRLCVCInteractionImpl extends CertValidationChannelInteractionImpl
{
  
  public CRLCVCInteractionImpl(Connection connection)
  {
    super(connection);
    //CHANNELSTR="CRL";
  }
  
  /*protected void init() throws ResourceException
  {
    try
    {
      Vector dps = new Vector();
      dps.add( new IssuingDistributionPoint( "http://pilotonsitecrl.ace.es/extendnowITClass3/LatestCRL.crl" ) );
      CRLManager.instance().load( dps );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Top level.CRLManager init", e);
      // javax.resource.ResourceException does not support chained Exceptions
      throw new ResourceException("Error in CRLManager init." + e.getMessage());
    }
  }*/
  
  protected CRLValidationResponse getCRLs(CRLSelector sel)
  {
    CRLValidationResponse crlResponse = null;
    
    try
    {
      Collection col = CRLManager.instance().getCRLs(sel);
      if ( col != null )
        crlResponse = new CRLValidationResponse ( col );
    }
    catch(Exception e)
    {
      pkiva.log.LogManager.getLogger(this.getClass()).debug("Top level.getting CRLs:" + e);
      crlResponse = new CRLValidationResponse ( e );
    }
    
    return crlResponse;
  }
}
