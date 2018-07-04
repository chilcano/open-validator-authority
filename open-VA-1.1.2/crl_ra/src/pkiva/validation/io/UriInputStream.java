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
package pkiva.validation.io;

import java.io.*;



public abstract class UriInputStream extends InputStream
{
  
  
  /**
   * Realiza la conexi�n con la uri especificada.
   *
   * @param
   * @return
   * @exception CertificateValidationErrorException Se lanza la excepci�n en caso de suceder alg�n tipo
   * de error en la conexi�n:
   * 		Si no se puede construir la URL -> URI_ERROR_01
   *		Si no se puede conectar con la URL -> URI_ERROR_02
   *		Si no se pueden obtener datos de la URL -> URI_ERROR_03
   *		Si existe alg�n problema al obtener la conexi�n -> URI_ERROR_04
   */
  
  public abstract void open() throws IOException;
  
}
