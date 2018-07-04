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


import javax.resource.NotSupportedException;
import javax.resource.ResourceException;
import javax.resource.cci.IndexedRecord;
import javax.resource.cci.MappedRecord;
import javax.resource.cci.RecordFactory;

public class CertValidationChannelRecordFactoryImpl implements RecordFactory
{
  
  private static final String MAPPED_RECORD_NOT_SUPPORTED_ERROR = "Mapped record not supported";
  private static final String INVALID_RECORD_NAME = "Invalid record name";
  
  public CertValidationChannelRecordFactoryImpl()
  {
    super();
  }
  
  public MappedRecord createMappedRecord(String recordName) throws ResourceException
  {
    throw new NotSupportedException(MAPPED_RECORD_NOT_SUPPORTED_ERROR);
  }
  
  public IndexedRecord createIndexedRecord(String recordName) throws ResourceException
  {
    CertValidationChannelIndexedRecordImpl record = null;
    if ((recordName.equals(CertValidationChannelIndexedRecordImpl.INPUT))
    || (recordName.equals(CertValidationChannelIndexedRecordImpl.OUTPUT)))
    {
      record = new CertValidationChannelIndexedRecordImpl();
      record.setRecordName(recordName);
    }
    if (record == null)
    {
      throw new ResourceException(INVALID_RECORD_NAME);
    } else
    {
      return record;
    }
  }
  
}
