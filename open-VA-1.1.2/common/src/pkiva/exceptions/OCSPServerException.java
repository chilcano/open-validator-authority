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
package pkiva.exceptions;

/**
 *
 * @author  diriarte
 */
public class OCSPServerException extends OCSPValidationException
{
  // -------------------- Error codes -------------------- //
  // Los codigos de error son los que especifica [RFC2560]
  // son equivalentes a org.bouncycastle.ocsp.OCSPRespStatus, pero se replican para no obligar a usar el provider BC
  /** Error en el formato de la petición */
  public static final int MALFORMED_REQUEST = 1;
  /** Error interno en el servidor de OCSP */
  public static final int INTERNAL_ERROR = 2;
  /** El servidor no puede contestar(intentelo mas tarde) */
  public static final int TRY_LATER = 3;
  /** La petición no esta firmada */
  public static final int SIGREQUIRED = 5;
  /** El servidor no puede autenticarte */
  public static final int UNAUTHORIZED = 6;
  
  // Pensar en anyadir este otro codigo */
  /** Server doesn't known about certificate chain validity */
  //public static final int UNKNOWN = 2;
  
  
  protected static final String UNKNOWN_ERROR = "Error desconocido:";
  
  protected static final String[] messages =
  {
    null,
    "Error en el formato de la petición (1)",
    "Error interno en el servidor de OCSP (2)",
    "El servidor no puede contestar (intentelo mas tarde) (3)",
    null,
    "La petición no esta firmada (5)",
    "El servidor no puede autenticarte (6)"
  };
  
  protected int status;
  
  /** Creates a new instance of OCSPServerException */
  public OCSPServerException(int status)
  {
    super();
    this.status = status;
  }
  
  /** Getter for property status.
   * @return Value of property status.
   *
   */
  public int getStatus()
  {
    return status;
  }
  
  public String getMessage()
  {
    String message = null;
    
    try
    {
      message = messages[status];
    }
    catch ( Throwable e )
    {
    }
    
    return ( message != null )? message : UNKNOWN_ERROR + status;
  }
}
