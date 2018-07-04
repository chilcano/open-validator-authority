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
package pkiva.log;

/**
 * This class define constants to be used when auditing keys
 */
public class AuditKeys {

  public final static int CERT_ISSUER = 1; /* String */
  public final static int CERT_SUBJECT = 2;  /* String */
  public final static int CERT_SERIAL_NUMBER = 3;  /* String */
  public final static int CERT_FINGERPRINT = 4;  /* String */
  public final static int POLICIES = 5;  /* String */
  public final static int VALIDATION_CHANNEL = 6;  /* String */
  public final static int VALIDATION_STATE = 7; /* String (int) */
  public final static int REVOCATION_OBJECT = 8;  /* Binary */
  public final static int POLICY_TREE = 9;  /* String */
  public final static int TRUST_ANCHOR_SUBJECT = 10; /* String */
  public final static int TRUST_ANCHOR_SERIAL_NUMBER = 11; /* String */
  public final static int TRUST_ANCHOR_FINGERPRINT = 12; /* String */
  public final static int DATA_EXTRACTION_PATH = 13; /* String */ 
  public final static int DATA_EXTRACTION_ITEM = 14;  /* String or binary */
  public final static int URL = 15;  /* String */
  public final static int CRL = 16;  /* Binary */  
  public final static int SUCCESS = 17;  /* String (boolean)*/
  public final static int PKCS7 = 18;  /* Binary */  
  public final static int CONTENT = 19;  /* Binary */  
  public final static int DIGEST = 20;  /* Binary */  
  public final static int INTERNAL_ERROR = 99; /* String */

}
