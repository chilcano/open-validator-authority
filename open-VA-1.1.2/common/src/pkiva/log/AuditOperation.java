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

import java.util.*;
import java.io.*;

/**
 * Base class to audit operations.
 * There will be a child class fro every audited operation.
 * Also define constants to be used when auditing operations
 */
public abstract class AuditOperation {

  public final static int CERTIFICATE_VALIDATION = 1;
  public final static int CERTIFICATE_DATA_EXTRACTION = 2;
  public final static int CRL_INSTALL = 3;
  public final static int LDAP_LOAD = 4;
  public final static int SIGNATURE_VALIDATION = 5;

  protected Hashtable request;
  protected Hashtable response;
  protected int operationName;

  protected AuditOperation ( int name )
  {
    request = new Hashtable();
    response = new Hashtable();
    this.operationName = name;
  }

  public Hashtable getRequest ( )
  {
    return request;
  }

  public Hashtable getResponse ( )
  {
    return response;
  }

  public int getOperation ( )
  {
    return operationName;
  }

  public void setError ( Throwable t )
  {
    addToResponse ( AuditKeys.INTERNAL_ERROR, AuditValue.newAsVarchar( trace2String ( t ) ) );
  }

  public String toString ( )
  {
    StringBuffer sb = new StringBuffer ( );

    sb.append ( "Operation: " ).append ( this.operationName ).append ( "\n" );
    sb.append ( "Request Parameters:\n\t" ).append ( this.request ).append ( "\n" );
    sb.append ( "Response Parameters:\n\t" ).append ( this.response ).append ( "\n" );

    return sb.toString();
  }

  protected void addToRequest ( int key, AuditValue value )
  {
    addToHashtable ( this.request, key, value );
  }

  protected void addToResponse ( int key, AuditValue value )
  {
    addToHashtable ( this.response, key, value );
  }

  private void addToHashtable ( Hashtable table, int key, AuditValue value )
  {
    table.put ( new Integer ( key ), value );
  }

  static private String trace2String ( Throwable t )
  {
    StringWriter stringWriter = new StringWriter();
    t.printStackTrace( new PrintWriter( stringWriter ) );
    return stringWriter.toString();
  }

}
