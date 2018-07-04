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

import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import javax.resource.cci.Interaction;
import javax.resource.cci.InteractionSpec;

public class OCSPInteractionSpecProxy implements java.lang.reflect.InvocationHandler
{
  
  private Object obj;
  
  public static Object newInstance(Object obj)
  {
    Object ret= java.lang.reflect.Proxy.newProxyInstance(
    OCSPInteractionSpec.class.getClassLoader(),
    new Class[]
    { OCSPInteractionSpec.class },
    new OCSPInteractionSpecProxy(obj));
    return ret;
  }
  
  private OCSPInteractionSpecProxy(Object obj)
  {
    this.obj = obj;
  }
  
  public Object invoke(Object proxy, Method m, Object[] args)	throws Throwable
  {
    Object result;
    try
    {
      result = m.invoke(obj, args);
    } catch (InvocationTargetException e)
    {
      throw e.getTargetException();
    }
    return result;
  }
}


