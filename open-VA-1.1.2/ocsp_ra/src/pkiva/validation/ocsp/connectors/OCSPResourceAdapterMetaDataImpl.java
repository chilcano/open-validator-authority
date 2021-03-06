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

import javax.resource.cci.ResourceAdapterMetaData;

public class OCSPResourceAdapterMetaDataImpl implements ResourceAdapterMetaData
{
  
  private static final String ADAPTER_VERSION = "1.0";
  private static final String ADAPTER_VENDOR_NAME = "e-xtendnow";
  private static final String ADAPTER_NAME = "OCSP Resource Adapter";
  private static final String ADAPTER_DESCRIPTION = "A simple sample resource adapter";
  private static final String SPEC_VERSION = "1.0";
  private static final String[] INTERACTION_SPECS_SUPPORTED =
  { "pkiva.ldap.connectors.OCSPInteractionSpecImpl" };
  
  public OCSPResourceAdapterMetaDataImpl()
  {
    super();
  }
  
  public String getAdapterVersion()
  {
    return ADAPTER_VERSION;
  }
  
  public String getAdapterVendorName()
  {
    return ADAPTER_VENDOR_NAME;
  }
  
  public String getAdapterName()
  {
    return ADAPTER_NAME;
  }
  
  public String getAdapterShortDescription()
  {
    return ADAPTER_DESCRIPTION;
  }
  
  public String getSpecVersion()
  {
    return SPEC_VERSION;
  }
  
  public String[] getInteractionSpecsSupported()
  {
    return INTERACTION_SPECS_SUPPORTED;
  }
  
  public boolean supportsExecuteWithInputAndOutputRecord()
  {
    return true;
  }
  
  public boolean supportsExecuteWithInputRecordOnly()
  {
    return false;
  }
  
  public boolean supportsLocalTransactionDemarcation()
  {
    return false;
  }
  
}
