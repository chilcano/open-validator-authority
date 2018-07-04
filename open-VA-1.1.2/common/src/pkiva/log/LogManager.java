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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.*;

/** This class provides a central point for obtaining Loggers. */
public class LogManager {

    /** Returns a Logger for given identifier.
     * @param s The identifier associated to the logger
     * @return A logger for given name.
     */
    public static Log getLogger(String s){
		return LogFactory.getLog(s);
    }
    
    /** Returns a Logger for given class. Logger identifier is obtained from class name.
     * @param c The class whose name will be the identifier associated to the logger.
     * @return A logger for given class name.
     */    
    public static Log getLogger(Class c){
		return LogFactory.getLog(c);
    }

    public static boolean isTraceEnabled(Class c) {
        return getLogger(c).isTraceEnabled();
    }

    public static boolean isTraceEnabled(String s) {
        return getLogger(s).isTraceEnabled();
    }

    public static boolean isDebugEnabled(Class c) {
        return getLogger(c).isDebugEnabled();
    }

    public static boolean isDebugEnabled(String s) {
        return getLogger(s).isDebugEnabled();
    }

    public static boolean isInfoEnabled(Class c) {
        return getLogger(c).isInfoEnabled();
    }

    public static boolean isInfoEnabled(String s) {
        return getLogger(s).isInfoEnabled();
    }

    public static boolean isWarnEnabled(Class c) {
        return getLogger(c).isWarnEnabled();
    }

    public static boolean isWarnEnabled(String s) {
        return getLogger(s).isWarnEnabled();
    }

    public static boolean isErrorEnabled(Class c) {
        return getLogger(c).isErrorEnabled();
    }

    public static boolean isErrorEnabled(String s) {
        return getLogger(s).isErrorEnabled();
    }
}
