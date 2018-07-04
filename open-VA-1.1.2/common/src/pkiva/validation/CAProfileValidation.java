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
package pkiva.validation;

import pkiva.exceptions.*;
import java.security.cert.*;

public class CAProfileValidation {

  
  
  public static void setCAAccepted(X509Certificate certificate, String profileId,boolean accepted) throws CertificateException{
  	pkiva.log.LogManager.getLogger(CAProfileValidation.class).info("CAProfileValidation .setCAAccepted(). Parameters: certificate=" + certificate + ", profileId=" + profileId + ", accepted=" + accepted);
  	
  	String strCA=certificate.getIssuerDN().toString();
  	CAProfileAssociationStore as=CAProfileAssociationStore.getInstance();
  	if (accepted)
  		as.addAssociation(strCA,profileId);
  	else
  		as.removeAssociation(strCA,profileId);
  		
  	
  }
  
  public static boolean isCAAccepted(X509Certificate certificate, String profileId) throws CertificateException {
  	pkiva.log.LogManager.getLogger(CAProfileValidation.class).info("CAProfileValidation .isCAAccepted(). Parameters: certificate=" + certificate + ", profileId=" + profileId);
  	
  	String strCA=certificate.getIssuerDN().toString();
  	CAProfileAssociationStore as=CAProfileAssociationStore.getInstance();
  	return as.existsAssociation(strCA,profileId);
  }
 
  
}
