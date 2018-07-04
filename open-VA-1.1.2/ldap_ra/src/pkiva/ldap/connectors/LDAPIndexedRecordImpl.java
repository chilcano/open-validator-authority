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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import javax.resource.cci.IndexedRecord;

public class LDAPIndexedRecordImpl implements LDAPIndexedRecord
{
  
  private ArrayList list = new ArrayList();
  private String name;
  private String description;
  
  public LDAPIndexedRecordImpl()
  {
    super();
  }
  
  public String getRecordName()
  {
    return name;
  }
  
  public void setRecordName(String name)
  {
    this.name = name;
  }
  
  public void setRecordShortDescription(String description)
  {
    this.description = description;
  }
  
  public String getRecordShortDescription()
  {
    return description;
  }
  
  public int size()
  {
    return list.size();
  }
  
  public boolean isEmpty()
  {
    return list.isEmpty();
  }
  
  public boolean contains(Object o)
  {
    return list.contains(o);
  }
  
  public Iterator iterator()
  {
    return list.iterator();
  }
  
  public Object[] toArray()
  {
    return list.toArray();
  }
  
  public Object[] toArray(Object[] a)
  {
    return list.toArray(a);
  }
  
  public boolean add(Object o)
  {
    return list.add(o);
  }
  
  public boolean remove(Object o)
  {
    return list.remove(o);
  }
  
  public boolean containsAll(Collection c)
  {
    return list.containsAll(c);
  }
  
  public boolean addAll(Collection c)
  {
    return list.addAll(c);
  }
  
  public boolean addAll(int index, Collection c)
  {
    return list.addAll(index, c);
  }
  
  public boolean removeAll(Collection c)
  {
    return list.removeAll(c);
  }
  
  public boolean retainAll(Collection c)
  {
    return list.retainAll(c);
  }
  
  public void clear()
  {
    list.clear();
  }
  
  public Object get(int index)
  {
    return list.get(index);
  }
  
  public Object set(int index, Object o)
  {
    return list.set(index, o);
  }
  
  public void add(int index, Object o)
  {
    list.add(index, o);
  }
  
  public Object remove(int index)
  {
    return list.remove(index);
  }
  
  public int indexOf(Object o)
  {
    return list.indexOf(o);
  }
  
  public int lastIndexOf(Object o)
  {
    return list.lastIndexOf(o);
  }
  
  public ListIterator listIterator()
  {
    return list.listIterator();
  }
  
  public ListIterator listIterator(int index)
  {
    return list.listIterator(index);
  }
  
  public List subList(int fromIndex, int toIndex)
  {
    return list.subList(fromIndex, toIndex);
  }
  
  public Object clone() throws CloneNotSupportedException
  {
    throw new CloneNotSupportedException();
  }
  
}

