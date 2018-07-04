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
package pkiva.validation;

import java.util.*;

public  class CAProfileAssociationStore {

  Set m_associations;
  private static CAProfileAssociationStore instance;
  static{
  	instance=new CAProfileAssociationStore();
  	instance.init();
  }  
  
  private CAProfileAssociationStore(){
  }  
  
  private void init(){
  	m_associations=new HashSet();
  }
  
  synchronized public static CAProfileAssociationStore getInstance(){
  	return instance;
  }
  
  public void addAssociation(String strCA,String profileId){
  	m_associations.add(new Association(strCA,profileId));
  }
  
  public void removeAssociation(String strCA,String profileId){
  	Association a=new Association(strCA,profileId);
  	if (m_associations.contains(a))
  		m_associations.remove(a);
  }
  
  public boolean existsAssociation(String strCA,String profileId){
  	return m_associations.contains(new Association(strCA,profileId));
  }
}

class Association{
	private String strCA;
	private String ProfileId;
	
	public Association(String strCA,String ProfileId){
		this.strCA=strCA;
		this.ProfileId=ProfileId;
	}
	
	public boolean equals(Object o) {
    		return ((o != null) && (this.getClass() == o.getClass()) &&
      			(strCA.equals(
      					(
      					(Association)
      					o)
      					.strCA
      				      ) && 
   			  ProfileId.equals(
   			  			(
   			  				(Association)o
   			  			).ProfileId
					  )   			  		
   			));
  	}

	
}
