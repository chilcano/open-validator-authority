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
package pkiva.ldap.connectors;

import java.beans.PropertyChangeListener;
import javax.resource.cci.InteractionSpec;

public interface LDAPInteractionSpec extends InteractionSpec {
	public static final String LOAD_DATA_FUNCTION = "loadData";
	public static final String GET_ELEMENT_FUNCTION = "getEstructuralElement";
	public static final String COLLECT_CAS_FUNCTION = "collectCAs";
	public static final String GET_TOP_ELEMENTS_FUNCTION = "getTopLevelElements";
	public static final String GET_LAST_UPDATED_FUNCTION = "getLastUpdated";
	public String getFunctionName();
	public void setFunctionName(String functionName);
}
