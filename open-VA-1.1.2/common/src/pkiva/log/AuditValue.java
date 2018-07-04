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
 * This class acts as a value wrapper
 */
public class AuditValue {

  public final static int VARCHAR = 1; /* String */
  public final static int BLOB = 2;  /* byte[] */

  protected Object object;
  protected int type;

  public static AuditValue newAsVarchar ( String st )
  {
    if ( st == null )
      return new AuditValue ( new String(), VARCHAR );
    else
      return new AuditValue ( st, VARCHAR );
  }

  public static AuditValue newAsBlob ( byte[] b )
  {
    if ( b == null )
      return new AuditValue ( new byte[0], BLOB );
    else
      return new AuditValue ( b, BLOB );
  }

  protected AuditValue ( Object obj, int t )
  {
    this.object = obj;
    this.type = t;
  }

  public int getType ( )
  {
    return this.type;
  }

  public String getAsVarchar ( )
  {
    if ( this.getType() == AuditValue.VARCHAR )
      return (String) object;
    else
      return null;
  }

  public byte[] getAsBlob ( )
  {
    if ( this.getType() == AuditValue.BLOB )
      return (byte[]) object;
    else
      return null;
  }

    public String toString() {
        StringBuffer sb = new StringBuffer();

        sb.append(super.toString()).append(".Type[").append(this.type == AuditValue.VARCHAR ? "VARCHAR" : "BLOB").append("]");
        if (type == AuditValue.VARCHAR) {
            sb.append(".Value[").append(object).append("]");
        }

        return sb.toString();     
    }

}
