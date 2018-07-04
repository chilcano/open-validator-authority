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
package pkiva.validation.crl;

import java.util.*;
import java.security.cert.*;
import pkiva.validation.io.*;
import pkiva.exceptions.*;
import pkiva.providers.TimeProvider;
import pkiva.services.ServiceLocator;

/**
 * Class: CRLWrapper
 *
 */
/* diriarte 20040311 - Eliminada la optimizacion de trabajar offline. */

public class CRLWrapper
{
  
  private IssuingDistributionPoint idp;
  private X509CRL crl;
    private Date fetchDate;

    // diriarte 20050421, posibility not to use Threshold
    //private static final int THRESHOLD = 15 * 24 * 60; // days -> minutes
    private static final int THRESHOLD = -1; // days -> minutes

  /**
   * CRLWrapper class constructor
   * @param
   */
  public CRLWrapper( IssuingDistributionPoint dp) throws CRLFetchingException
  {
      this.idp = dp;
      this.crl = null;
      this.fetchDate = null;

    // once we have dp, let's fetch crl
    update();
  }
  
  public X509CRL getCRL( ) throws CRLFetchingException
  {
    // if we are requested for a CRL, we'd better provide it up-to-date
    checkUpdate( );
    
    return this.crl;
  }
  
  /*public X509CRL getCRL( boolean checkUpdate )
  {
    if ( checkUpdate )
      checkUpdate( );
   
    // even if checkUpdate is false we shouldn't return a null crl
    else if ( this.crl == null )
      update();
   
    return this.crl;
  }*/
  
  public boolean match( IssuingDistributionPoint dp )
  {
    return this.idp.equals( dp );
  }
  
  public boolean match( CRLSelector sel ) throws CRLFetchingException
  {
	  // diriarte: 20051114, we are not working up-to-date here
    //checkUpdate();
    
    // if crl is null, we've got a problem
    if ( crl == null )
    {
      if (pkiva.log.LogManager.isWarnEnabled(this.getClass()))
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't match after update.CRL is NULL");
      return false;
    }
    
    if ( sel == null )
    {
      if (pkiva.log.LogManager.isWarnEnabled(this.getClass()))
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't match after update.Selector is NULL");
      return false;
    }
    
    return sel.match( this.crl );
  }
  
  public String toString()
  {
    StringBuffer out = new StringBuffer( this.getClass().getName() );
    out.append( " [" ).append( this.idp.toString() ).append( "]" );
    
    return out.toString();
  }

  /** Getter for property idp.
   * @return Value of property idp.
   *
   */
  public pkiva.validation.crl.IssuingDistributionPoint getIdp()
  {
    return idp;
  }
  
  /*public boolean match( CRLSelector sel, boolean workOffline )
  {
   
    // checkear si viene date en el sel, en ese caso hay que actualizar siempre
   
    // check if we are requested not to update crl
    // we must update if crl is null
    if ( ( !workOffline ) || ( crl == null ) )
      checkUpdate();
   
    // if crl is null, we've got a problem
    if ( ( crl == null ) || ( sel == null ) )
      return false;
   
    return sel.match( this.crl );
  }*/
  
  private void checkUpdate() throws CRLFetchingException
  {
    if ( needsUpdate() )
    {
      if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
          pkiva.log.LogManager.getLogger(this.getClass()).debug("I Need Update::" + this);
      update();
    }
    else if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
      pkiva.log.LogManager.getLogger(this.getClass()).debug("I'm up-to-date::" + this);

  }
  
  private void update( ) throws CRLFetchingException
  {
    try
    {
      if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
          pkiva.log.LogManager.getLogger(this.getClass()).debug("Updating::" + this);
      
      synchronized ( this )
      {
        // si es de tipo URI vamos a buscar el CRL
        // *** We'll asume IDPs from certificate will be URIs ***
        if ( ( IssuingDistributionPoint.URI_DPTYPE.equals ( this.idp.getDPType () ) )
              || ( IssuingDistributionPoint.UNKNOWN_DPTYPE.equals ( this.idp.getDPType () ) ) )
        {
          this.crl = FetcherManager.instance().getCRL( this.idp.getLocation(), this.idp.getAttributes() );
          if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).debug("CRL:" + this.crl);
          if ( needsUpdate(false) )
          {
            if (pkiva.log.LogManager.isWarnEnabled(this.getClass()))
                pkiva.log.LogManager.getLogger(this.getClass()).warn("We've got a expired CRL after fetching. Must discard");
            this.crl = null;
          } // end if ( needsUpdate() )
        } // end if ( IssuingDistributionPoint.URI_DPTYPE ...
        else if ( IssuingDistributionPoint.INCOMPLETE_DPTYPE.equals ( this.idp.getDPType () ) )
        {
          if (pkiva.log.LogManager.isWarnEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).warn("Found INCOMPLETE IssuingDistributionPoint. Should not fetch: " + this.idp.getLocation());
        }
        else
        {
          if (pkiva.log.LogManager.isWarnEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't Fetch IssuingDistributionPoint with type:" + this.idp.getDPType ());
        }
      } // end synchronized

        if (this.crl != null) {
            this.fetchDate = TimeProvider.getCurrentTime().getTime();
            if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Updating fetchDate for CRL: " + this.idp.getLocation());
        }
    }
    catch ( FetchingException fe )
    {
      throw new CRLFetchingException("Couldn't fetch::" + this, fe );
    }
  }
  
  private boolean needsUpdate( )
  {
    return needsUpdate ( true );
  }
  
  private boolean needsUpdate( boolean doThreshold )
  {
    if ( this.crl == null )
      return true;

      if (pkiva.log.LogManager.isDebugEnabled(this.getClass())) {
          pkiva.log.LogManager.getLogger(this.getClass()).debug("crl.getThisUpdate():" + crl.getThisUpdate());
          pkiva.log.LogManager.getLogger(this.getClass()).debug("crl.getNextUpdate():" + crl.getNextUpdate());
      }

    // has expired ??
    Date nextUpdate;
    if ( doThreshold )
    {
        if (this.fetchDate == null) {
            if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Asuming low value for threshold interval crl.thisUpd:: " + crl.getThisUpdate());
            nextUpdate = fitThreshold(crl.getThisUpdate(), crl.getNextUpdate());
        } else {
            if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
                pkiva.log.LogManager.getLogger(this.getClass()).debug("Asuming low value for threshold interval this.fetchDate:: " + this.fetchDate);
            nextUpdate = fitThreshold(this.fetchDate, crl.getNextUpdate());
        }

    }
    else
    {
      nextUpdate = crl.getNextUpdate();
      if ( nextUpdate == null )
      {
        // we know nothing, let's force update returning yesterday
        nextUpdate = getYesterday ();
      }
    }

    Date now = TimeProvider.getCurrentTime().getTime();
    
    return now.after( nextUpdate );
  }
  
  private int getThreshold() // minutes
  {
      try{
          ServiceLocator svcLoc=ServiceLocator.getInstance();
          String s = svcLoc.getProperty("pkiva.validation.CRLThreshold");
          if(s!=null){
              return Integer.parseInt(s);
          }
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Property not found getting threshold, using default: " + THRESHOLD);
      }
      catch( Throwable e){
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Error getting threshold from properties, using default: " + THRESHOLD,e);
      }
      return THRESHOLD;
  }
  
  private Date fitThreshold( Date thisUpd, Date nextUpd )
  {
    Calendar cal = Calendar.getInstance();

//      if ( ( thisUpd == null ) && ( nextUpd == null ) )
    if ( thisUpd == null )
    {
      // We know nothing ab crl.thisUpd, let's force update returning yesterday
      if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
          pkiva.log.LogManager.getLogger(this.getClass()).debug("We know nothing ab crl.thisUpd, let's force update returning yesterday");
      return getYesterday ();
    }

      // diriarte 20050421, posibility not to use Threshold
      int threshold = getThreshold();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("THRESHOLD:" + threshold);
      if (threshold < 0) {
          if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).debug("Threshold is negative, returning crl.nextUpd (yesterday if null):" + nextUpd);
          return nextUpd != null ? nextUpd : getYesterday ();
      }

    // find out thisUpdate + threshold
    cal.setTime( thisUpd );
    cal.add( Calendar.MINUTE, threshold );
    Date thresholdPlusUpdate = cal.getTime();
    
    // let's return smaller date
      if ((nextUpd == null) || (nextUpd.after(thresholdPlusUpdate))) {
          if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).debug("crl.nextUpd is null or too far, returning " + thresholdPlusUpdate);
          return thresholdPlusUpdate;
      } else {
          if (pkiva.log.LogManager.isDebugEnabled(this.getClass()))
              pkiva.log.LogManager.getLogger(this.getClass()).debug("returning crl.nextUpd:  " + nextUpd);
          return nextUpd;
      }
  }

  protected static Date getYesterday ()
  {
      Calendar cal = Calendar.getInstance();
      cal.setTime( TimeProvider.getCurrentTime().getTime() );
      cal.add(Calendar.DATE, -1);
      return cal.getTime();
  }
  
		// diriarte: 20051114
  public boolean equals( Object obj )
  {
    boolean eq = super.equals( obj );
    
    // if references are not equal, let's find out about IssuingDistributionPoint
    if ( ! eq )
      if ( obj instanceof CRLWrapper )
      {
        CRLWrapper crlw = (CRLWrapper) obj;

        eq = this.idp.equals( crlw.getIdp() );
      }
    
    return eq;
  }

		// diriarte: 20051114
  public int hashCode()
	{	
		if ( this.idp != null )
		{
			return idp.hashCode();
		} else
		{
			return super.hashCode();
		}
	}
	 

}



