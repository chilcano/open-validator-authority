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
package pkiva.providers;

import java.util.Calendar;
import java.util.Date;


//convenience central point that provides a portable way to express how the dates are obtained.

public class TimeProvider
	{
	public static Calendar getCurrentTime()
		{
		//for now very simple, only get a system date, stated that the machine must have out-of-band time synchronization 
		//methods (i.e. trusted time source)

		Calendar validDate = Calendar.getInstance();

//		validDate.setTime(new Date(System.currentTimeMillis()));

//      validDate.setTime(new Date(System.currentTimeMillis()/* - (31570560000L*4) /*n years*/ ));

//        Like other locale-sensitive classes, Calendar provides a class method, getInstance, for getting a generally useful object of this type.
//        Calendar's getInstance method returns a Calendar object whose time fields have been initialized with the current date and time:
//
//             Calendar rightNow = Calendar.getInstance();

		return validDate;
		}
	}
