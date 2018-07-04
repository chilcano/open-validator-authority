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
package pkiva.utils;

import org.apache.log4j.Logger;

/**
 * @author rnavalon
 */
public final class Log {

	private final static Logger logger = Logger.getLogger("PKIVA");
	
	public static void info( Object msg ) {
		logger.info( msg );
	}
	
	public static void warning( Object msg ) {
		logger.warn( msg );
	}
	
	public static void warning( Object msg , Throwable e ) {
		logger.warn(msg,e);
	}
	
	public static void error( Object msg ) {
		logger.error( msg );
	}
	
	public static void error( Object msg , Throwable t ) {
		logger.error( msg , t );
	}
	
	public static void critical( Object msg ) {
		logger.fatal( msg );
	}
	
	public static void critical( Object msg , Throwable t ) {
		logger.fatal( msg , t );
	}
	
	public static void debug( Object msg ) {
		logger.debug( msg );
	}
}
