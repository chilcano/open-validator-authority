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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

import javax.resource.cci.InteractionSpec;

public class LDAPInteractionSpecImpl implements LDAPInteractionSpec {
	
	private String functionName;
	protected transient PropertyChangeSupport propertyChange;

	public LDAPInteractionSpecImpl() {
		super();
	}

	public String getFunctionName() {
		return functionName;
	}

	public void setFunctionName(String functionName) {
		String oldFunctionName = functionName;
		this.functionName = functionName;
		firePropertyChange("FunctionName", oldFunctionName, functionName);
	}

	public synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
		getPropertyChange().addPropertyChangeListener(listener);
	}

	public synchronized void addPropertyChangeListener(String propertyName,	PropertyChangeListener listener) {
		getPropertyChange().addPropertyChangeListener(propertyName, listener);
	}

	
	public void firePropertyChange(PropertyChangeEvent evt) {
		getPropertyChange().firePropertyChange(evt);
	}

	public void firePropertyChange(	String propertyName, int oldValue, int newValue) {
		getPropertyChange().firePropertyChange(propertyName, oldValue, newValue);
	}

	public void firePropertyChange(	String propertyName, Object oldValue,Object newValue) {
		getPropertyChange().firePropertyChange(propertyName, oldValue, newValue);
	}

	public void firePropertyChange(	String propertyName, boolean oldValue, 	boolean newValue) {
		getPropertyChange().firePropertyChange(propertyName, oldValue, newValue);
	}

	protected PropertyChangeSupport getPropertyChange() {
		if (propertyChange == null) 
			propertyChange = new PropertyChangeSupport(this);
		return propertyChange;
	}

	public synchronized boolean hasListeners(String propertyName) {
		return getPropertyChange().hasListeners(propertyName);
	}


	public synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
		getPropertyChange().removePropertyChangeListener(listener);
	}

	public synchronized void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
				getPropertyChange().removePropertyChangeListener(propertyName, listener);
	}
}
