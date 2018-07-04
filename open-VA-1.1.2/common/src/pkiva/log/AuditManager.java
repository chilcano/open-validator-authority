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

import pkiva.exceptions.*;

/** This class provides a central point for obtaining Auditers. */
public class AuditManager {
    private static Hashtable auditers = new Hashtable();
    
    /** Returns a Auditer for given identifier.
     * @param s The identifier associated to the Auditer
     * @return A Auditer for given name.
     */
    public static pkiva.log.Auditer getAuditer(String s) throws AuditingException
    {
        Auditer auditer = (Auditer) auditers.get(s);
        if(auditer==null){
            auditers.put(s,auditer=new Auditer(s));
        }
        return auditer;
    }
    
    /** Returns a Auditer for given class. Auditer identifier is obtained from class name.
     * @param c The class whose name will be the identifier associated to the Auditer.
     * @return An Auditer for given class name.
     */    
    public static pkiva.log.Auditer getAuditer(Class c) throws AuditingException
    {
        return getAuditer(c.getName());
    }
    
    /** Returns a Auditer for given object. Auditer identifier is obtained from object's class name.
     * @param o The Object whose class name will be the identifier associated to the Auditer.
     * @return An Auditer for given class name.
     */    
    public static pkiva.log.Auditer getAuditer(Object o) throws AuditingException
    {
        if(o instanceof String)
            return getAuditer((String)o);
        if(o instanceof Class)
            return getAuditer((Class)o);
        return getAuditer(o.getClass());
    }
}
