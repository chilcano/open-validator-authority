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

import java.net.*;
import java.io.*;
import java.util.*;

import java.security.cert.X509Certificate;
import java.security.cert.CRLSelector;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CRL;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import javax.resource.cci.*;
import javax.resource.ResourceException;

import pkiva.ldap.*;
import pkiva.ldap.connectors.*;
import pkiva.services.*;
import pkiva.validation.crl.*;
import pkiva.validation.io.*;
import pkiva.exceptions.*;

public class CRLManager
{ //Singleton
  
  static private CRLManager m_instance = new CRLManager();
  
  private Set crlCache = new HashSet();
  
  static public CRLManager instance()
  {
    return m_instance;
  }
  
  protected CRLManager()
  {
    // carga inicial de la cache de CRLs
    try
    {
      Collection cas = getCAsFromLDAP();
      pkiva.log.LogManager.getLogger(this.getClass()).debug("getCAs::" + cas);
      Collection dps = getDPsFromCAs( cas );
      pkiva.log.LogManager.getLogger(this.getClass()).debug("got DPs from CAs (SIZE)::" + dps.size());
      pkiva.log.LogManager.getLogger(this.getClass()).debug("got DPs from CAs::" + dps);
      load( dps );
      pkiva.log.LogManager.getLogger(this.getClass()).info("CRL cache initial load performed.Cache size:" + crlCache.size());
      //pkiva.log.AuditManager.getAuditer(this.getClass()).audit("CRL cache initial load performed.Cache size:" + crlCache.size());
    }
    catch ( Exception e )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).error("Error loading from LDAP:", e);
    }

  }
  
  public Collection getCRLs( CRLSelector sel ) throws CRLFetchingException
  {
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Getting CRLs from selector::" + sel);
    
    // find out if we are requested to fetch CRLs from DPs
    Collection dps = getDPsFromSelector( sel );
    pkiva.log.LogManager.getLogger(this.getClass()).info("got DPs From Selector::" + dps);
    
    // we'll have here desired CRLs
    //Vector result = new Vector();
	// diriarte: 20051114
	// we'll have here desired CRLWrappers
    Set resultCRLWs = new HashSet();

	// diriarte: 20051114
	  synchronized (crlCache)
	  {
		pkiva.log.LogManager.getLogger(this.getClass()).info("Iterating in cache.Size::" + crlCache.size());
		Iterator cacheIterator = crlCache.iterator();
		
		// one and only iteration through CRL_Cache
		// we've got in dps DistributionPoints from Certificate
		while ( cacheIterator.hasNext() )
		{
		  CRLWrapper crlw = (CRLWrapper) cacheIterator.next();
		  pkiva.log.LogManager.getLogger(this.getClass()).debug("%%%% Iterating in cache.Element::" + crlw);

		  try
		  {
			if ( dps.contains( crlw.getIdp() ) )
			{
			  // we have to return this cached CRL requested by certificate's DP
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("CRL from DP cache HIT. crlw:" + crlw);
				resultCRLWs.add ( crlw );
				dps.remove( crlw.getIdp() );
			}
			else if ( crlw.match( sel ) ) // diriarte: 20051114, we are not working up-to-date here
			{
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("CRL matches selector. crlw:" + crlw);
				resultCRLWs.add ( crlw );
			}
		  }
		  catch ( CRLFetchingException fe )
		  {
			pkiva.log.LogManager.getLogger(this.getClass()).warn("Error fetching CRL", fe);
		  }
		} // end while cacheIterator
	  } // end sync

	// diriarte: 20051114
	  // and now fetch those crlw's

      // we'll have here desired CRLs
	  Set crls = new HashSet(resultCRLWs.size());

    pkiva.log.LogManager.getLogger(this.getClass()).info("Fetching CRLWs ::" + resultCRLWs);

		Iterator crlwIterator = resultCRLWs.iterator();
		
		while ( crlwIterator.hasNext() )
		{
			try
			{
			  CRLWrapper crlw = (CRLWrapper) crlwIterator.next();
				  X509CRL crl = crlw.getCRL();
				  if ( crl != null )
				  {
					crls.add( crl );
				  }
			}
			catch ( CRLFetchingException fe )
			{
			pkiva.log.LogManager.getLogger(this.getClass()).warn("Error fetching CRL", fe);
			}
		}



    // we have here dps whose CRLs were not cached, let's fetch'em
	// diriarte 20050513, if size now is lower than b4 (we've already got any CRL from 'dps'), we shouldn't get the rest...
	// it could not be 100% rigth, but helps to not fail in trying to fetch http://epscd2.catcert.net/crl/*.crl
	// uncomment this to delete this assertion ...
    crls.addAll( loadAndReturn( dps ) );
    
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Returning CRLs ::" + crls.size());
    return crls;
  }
  
  protected void load( Collection c ) throws CRLFetchingException
  {
    load( c, false );
  }
  
  protected Collection loadAndReturn( Collection c ) throws CRLFetchingException
  {
    return load( c, true );
  }
  
  protected Collection load( Collection c, boolean mustReturn ) throws CRLFetchingException
  {
    // in case we must return ...
    Vector crls = new Vector();
    
    Iterator i = c.iterator();
    pkiva.log.LogManager.getLogger(this.getClass()).info("Start loading CRLs. Return'em requested:" + mustReturn);
    while ( i.hasNext() )
    {
      IssuingDistributionPoint idp = (IssuingDistributionPoint) i.next();

      try
      {
        pkiva.log.LogManager.getLogger(this.getClass()).info("Loading " + idp);
        if ( ( idp.getDPType().equals( IssuingDistributionPoint.UNKNOWN_DPTYPE ) ) && ( ! seemsComplete ( idp ) ) )
        {
          pkiva.log.LogManager.getLogger(this.getClass()).debug("Incomplete in selector:" + idp);
          String selectorQualifier = new String( idp.getLocation() ).toUpperCase();
          pkiva.log.LogManager.getLogger(this.getClass()).debug("selectorQualifier:" + selectorQualifier);
          
          IssuingDistributionPoint incompleteIdpCandidate = null;

			// itera en la cache para completar un idp incompleto de un certificado, aqui no hay http conn.
		  synchronized (crlCache)
          {
			  Iterator cacheIterator = crlCache.iterator();
			  while ( cacheIterator.hasNext() )
			  {
				CRLWrapper crlw = (CRLWrapper) cacheIterator.next();
				IssuingDistributionPoint cacheIDP = crlw.getIdp();
				if ( cacheIDP.getDPType().equals( IssuingDistributionPoint.INCOMPLETE_DPTYPE ) )
				{
				  pkiva.log.LogManager.getLogger(this.getClass()).debug("Iterating in cache only INCOMPLETE.Element::" + crlw);
				  String base = getBase( cacheIDP.getLocation() );
				  String qualifier = new String( getQualifier( cacheIDP.getLocation(), base) ).toUpperCase();
				  pkiva.log.LogManager.getLogger(this.getClass()).debug("Base:" + base );
				  pkiva.log.LogManager.getLogger(this.getClass()).debug("Qual:" + qualifier );
				  if ( selectorQualifier.indexOf ( qualifier ) > 0 )
				  {
					pkiva.log.LogManager.getLogger(this.getClass()).debug("POSIBLE CANDIDATE:" + qualifier.length() );
					if ( ( incompleteIdpCandidate == null ) || ( incompleteIdpCandidate.getLocation().length() < cacheIDP.getLocation().length() ) )
					{
					  pkiva.log.LogManager.getLogger(this.getClass()).debug("Longer than previous" );
					  incompleteIdpCandidate = cacheIDP;

					}
				  }

			  pkiva.log.LogManager.getLogger(this.getClass()).debug("Incomplete in selector was :" + idp);
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("Best candidate:" + incompleteIdpCandidate);
			  String newLocation = base + selectorQualifier;
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("New location:" + newLocation);
			  IssuingDistributionPoint newIDP = new IssuingDistributionPoint ( newLocation, IssuingDistributionPoint.URI_DPTYPE );
			  newIDP.setAttributes ( cacheIDP.getAttributes() );
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("New IDP:" + newIDP);
			  idp = newIDP;

				} // end if ( cacheIDP.getDPType().equals( IssuingDistributionPoint.INCOMPLETE_DPTYPE ) )
			  } // end while
		  }


        } // end if ( idp.getDPType().equals( IssuingDistributionPoint.UNKNOWN_DPTYPE ) )

        
//        else
//        {
          CRLWrapper crlw = new CRLWrapper( idp );

			boolean doLog = false;
          synchronized (crlCache)
          {
			  doLog = crlCache.add( crlw );
          }

            if (doLog)
            {
			  pkiva.log.LogManager.getLogger(this.getClass()).info("Adding in cache:" + crlw);
			  pkiva.log.LogManager.getLogger(this.getClass()).info("Cache after: (SIZE)" + crlCache.size());
			  pkiva.log.LogManager.getLogger(this.getClass()).debug("Cache after: " + crlCache);
            }

		  if ( mustReturn )   // we can optimize it in case new CRLWrapper( idp ) doesn't fetch CRL
          {
            X509CRL crl = crlw.getCRL();
            if ( crl != null )
              crls.add( crl );
          }

//        } // end else if ( idp.getDPType().equals( IssuingDistributionPoint.UNKNOWN_DPTYPE ) )

      }
      catch ( Exception e )
      {
        pkiva.log.LogManager.getLogger(this.getClass()).error("Error fetching DP. Discarding: " + idp, e);
      }
    }
    
    pkiva.log.LogManager.getLogger(this.getClass()).info("End loading CRLs.");
    
    return crls;
  }

  protected static boolean seemsComplete ( IssuingDistributionPoint idp )
  {
    boolean complete = false;

    if ( idp != null )
    {
      String loc = idp.getLocation();
      if ( loc != null )
      {
        complete = loc.indexOf ( "://" ) > 0;
      }
    }

    return complete;
  }

  protected static String getBase ( String uri )
  {
    String base = null;

    if ( uri != null)
    {
      int i = uri.indexOf ( "://" );
      if ( i > 0 )
      {
        int last = uri.indexOf ( "/", i + 3);
        if ( last > 0 )
        {
          base = uri.substring ( 0, last + 1 );
        }
      }
    }

    return base;
  }
  
  protected static String getQualifier ( String uri, String base )
  {
    int l = base.length();
    return uri.substring ( l );
  }
  
  protected Collection getDPsFromSelector( CRLSelector sel ) throws CRLFetchingException
  {
    pkiva.log.LogManager.getLogger(this.getClass()).debug("Getting DPs from selector.");
    if ( ! ( sel instanceof X509CRLSelector ) )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't get DPs from selector with Class::" + sel.getClass() );
      return Collections.EMPTY_SET;
    }
    
    X509Certificate cert = ( (X509CRLSelector) sel ).getCertificateChecking();
    if ( cert == null )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't get DPs from selector without certificate" );
      return Collections.EMPTY_SET;
    }
    
    X509Extension dpExt = getExtension( cert, X509Extensions.CRLDistributionPoints );
    //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got dp Extension::" + dpExt);
    if ( dpExt == null )
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't get DPs from selector without CRLDistributionPoints extension" );
      return Collections.EMPTY_SET;
    }
    
    CRLDistPoint crldp = castCRLDistPoint( dpExt );
    //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got CRLDistPoint ::" + crldp);
    
	// diriarte: 20051114
	//Vector result = new Vector( );
	ArrayList result = new ArrayList();
    
    try
    {
      
      DistributionPoint[] dps = crldp.getDistributionPoints();
      if ( dps == null || dps.length == 0)
        return Collections.EMPTY_SET;
      
      pkiva.log.LogManager.getLogger(this.getClass()).info("Got DistributionPoints from certificate::" + dps.length);
	  result.add( checkDPName( dps[0].getDistributionPoint() ) );

      //for ( int i = 0; i < dps.length; i++)
      //{
        //result.addAll( checkDPName( dps[i].getDistributionPoint() ) );
        //result.add( checkDPName( dps[i].getDistributionPoint() ) );
      //}
    }
    catch ( Exception e )
    {
      throw new CRLFetchingException("Error getting DPs from CRLDistPoint", e );
    }
    
    return result;
  }
  
  protected X509Extension getExtension( X509Certificate cert, DERObjectIdentifier oid ) throws CRLFetchingException
  {
    try
    {
      byte[] certBytes = cert.getEncoded( );
      ByteArrayInputStream bais = new ByteArrayInputStream( certBytes );
      ASN1InputStream is = new ASN1InputStream(bais);
      DERObject asn1Cert = is.readObject();
      bais.close();
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got DERObject from cert");
      
      X509CertificateStructure certStruct = new X509CertificateStructure((ASN1Sequence)asn1Cert);
      TBSCertificateStructure tbscs = certStruct.getTBSCertificate();
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got TBSCertificateStructure");
      
      X509Extensions exts = tbscs.getExtensions();
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got Extensions::" + exts);
      if ( exts == null )
        return null;
      
      X509Extension dpExt = exts.getExtension( oid );
      
      return dpExt;
    }
    catch ( Exception e )
    {
      throw new CRLFetchingException("Error getting CRLDP extension from cert", e );
    }
  }
  
  protected CRLDistPoint castCRLDistPoint( X509Extension dpExt ) throws CRLFetchingException
  {
    try
    {
      ASN1OctetString value = dpExt.getValue();
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got OctetString::" + value);
      
      // we need to code bytes into a sequence object
      ByteArrayInputStream baisOctStr = new ByteArrayInputStream( value.getOctets() );
      ASN1InputStream asnIs = new ASN1InputStream( baisOctStr );
      ASN1Sequence seq = (ASN1Sequence) asnIs.readObject();
      baisOctStr.close();
      
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got Sequence ::" + seq);
      /*
       
        for (int i = 0; i != seq.size(); i++)
        {
            pkiva.log.LogManager.getLogger(this.getClass()).debug( "" );
            pkiva.log.LogManager.getLogger(this.getClass()).debug( "" + i );
            pkiva.log.LogManager.getLogger(this.getClass()).debug( "" + seq.getObjectAt(i).getClass() );
      ASN1Sequence seq2 = (ASN1Sequence) seq.getObjectAt(i);
      for (int j = 0; j != seq2.size(); j++)
      {
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t" + j );
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t" + seq2.getObjectAt(j).getClass() );
        DERTaggedObject tagged = (DERTaggedObject) seq2.getObjectAt(j);
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t.getTagNo()" + tagged.getTagNo() );
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t.getObject()" + tagged.getObject() );
        DERTaggedObject inside = (DERTaggedObject) tagged.getObject();
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t\t.getTagNo()" + inside.getTagNo() );
        pkiva.log.LogManager.getLogger(this.getClass()).debug( "\t\t.getObject()" + inside.getObject() );
       
      }
        }
       
      */
      
      return new CRLDistPoint( seq );
    }
    catch ( Exception e )
    {
      throw new CRLFetchingException("Error casting CRLDP extension to CRLDP object", e );
    }
  }
  
  /*
   * get IssuingDistributionPoint's from a DistributionPointName
   */
  //protected Collection checkDPName( DistributionPointName dpName )
  protected IssuingDistributionPoint checkDPName( DistributionPointName dpName )
  {
    //Vector idps = new Vector();
    
    //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got DistributionPointName::" + dpName);
    DERTaggedObject taggedDPName = (DERTaggedObject) dpName.toASN1Object();
    //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got DERObject::" + taggedDPName);
    
    /*
     DistributionPointName ::= CHOICE {
          fullName                [0]     GeneralNames,
          nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
     */
    if ( taggedDPName.getTagNo() == DistributionPointName.FULL_NAME )
    {
      DERSequence fullNameSeq = (DERSequence ) taggedDPName.getObject();
      //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got fullName::" + fullNameSeq);
      for ( int j = 0; j < fullNameSeq.size(); j++ )
      {
        DERTaggedObject fullNameTaggedObj = (DERTaggedObject) fullNameSeq.getObjectAt(j).getDERObject();
        //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got uri::" + uri);
        pkiva.log.LogManager.getLogger(this.getClass()).debug("Got fullNameTaggedObj, tagNo::" + fullNameTaggedObj.getTagNo());
        /*
          GeneralName ::= CHOICE {
               otherName                       [0]     AnotherName,
               rfc822Name                      [1]     IA5String,
               dNSName                         [2]     IA5String,
               x400Address                     [3]     ORAddress,
               directoryName                   [4]     Name,
               ediPartyName                    [5]     EDIPartyName,
               uniformResourceIdentifier       [6]     IA5String,
               iPAddress                       [7]     OCTET STRING,
               registeredID                    [8]     OBJECT IDENTIFIER }
         
         */
        
        if ( fullNameTaggedObj.getTagNo() == 6 ) //                uniformResourceIdentifier       [6]     IA5String,
        {
          //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got uri, object::" + uri.getObject());
          DEROctetString uriOct = (DEROctetString) fullNameTaggedObj.getObject();
          DERIA5String uriSt = new DERIA5String( uriOct.getOctets() );
          //pkiva.log.LogManager.getLogger(this.getClass()).debug("Got uriSt::" + uriSt.getString());
          //idps.add( new IssuingDistributionPoint( uriSt.getString() ) );
          return new IssuingDistributionPoint( uriSt.getString() );
        }
        else if ( fullNameTaggedObj.getTagNo() == 4 ) //                directoryName                   [4]     Name,
        {
          /*
             Name ::= CHOICE {
               RDNSequence }

             RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

             RelativeDistinguishedName ::=
               SET OF AttributeTypeAndValue

             AttributeTypeAndValue ::= SEQUENCE {
               type     AttributeType,
               value    AttributeValue }

             AttributeType ::= OBJECT IDENTIFIER

             AttributeValue ::= ANY DEFINED BY AttributeType

             DirectoryString ::= CHOICE {
                   teletexString           TeletexString (SIZE (1..MAX)),
                   printableString         PrintableString (SIZE (1..MAX)),
                   universalString         UniversalString (SIZE (1..MAX)),
                   utf8String              UTF8String (SIZE (1..MAX)),
                   bmpString               BMPString (SIZE (1..MAX)) }
          */

          DERSequence dirNameSeq = ( DERSequence ) fullNameTaggedObj.getObject();

          /*
          StringBuffer sb = new StringBuffer();
          for ( int dirNameSeqIndex = 0; dirNameSeqIndex < dirNameSeq.size(); dirNameSeqIndex++ )
          {
            DERSet relativeDistinguishedName = (DERSet) dirNameSeq.getObjectAt(dirNameSeqIndex).getDERObject();

            DERSequence attributeTypeAndValue = (DERSequence) relativeDistinguishedName.getObjectAt(0);

            DERObjectIdentifier attributeType = (DERObjectIdentifier) attributeTypeAndValue.getObjectAt(0);
            DERPrintableString attributeValue = (DERPrintableString) attributeTypeAndValue.getObjectAt(1);

            String type = translateOID( attributeType.getId() );
            String value = attributeValue.getString();
            pkiva.log.LogManager.getLogger(this.getClass()).debug("type::" + type );
            pkiva.log.LogManager.getLogger(this.getClass()).debug("value::" + value );

            sb.insert ( 0, value ).insert ( 0, '=' ).insert ( 0, type ).insert ( 0, ',' );
          }
          if ( sb.charAt (0) == ',' )
            sb.deleteCharAt ( 0 );
          pkiva.log.LogManager.getLogger(this.getClass()).debug("LDAP Incomplete::" + sb.toString() );

          idps.add( new IssuingDistributionPoint( sb.toString() ) );
          */

          X509Name x509name = new X509Name(dirNameSeq);
          // x509name.toString() doesn't do reverse
          String nameAsSt = x509name.toString(true, X509Name.RFC2253Symbols);
          pkiva.log.LogManager.getLogger(this.getClass()).debug("Traducimos con reverse X509Name:" + nameAsSt);
          //idps.add( new IssuingDistributionPoint( nameAsSt ) );
          return new IssuingDistributionPoint( nameAsSt );
        }
        else
        {
          pkiva.log.LogManager.getLogger(this.getClass()).warn("Got FullName (TaggedObj) from DistributionPointName with unexpected tag Number::" + fullNameTaggedObj.getTagNo());
        } // end if ( uri.getTagNo() == 6 )
      } // end for
    }
    else
    {
      pkiva.log.LogManager.getLogger(this.getClass()).warn("Can't get URI from DistributionPointName with nameRelativeToCRLIssuer");
    } // end if ( taggedDPName.getTagNo() == DistributionPointName.FULL_NAME )
    
    return null;
  }
  
  protected Collection getCAsFromLDAP( ) throws ResourceException {
//    int RESULT_FIELD=0;
//    String CONFIGPATH="connectors/LDAP/";
//    String CONNFACTORIES="ConnectionFactories";
//    String INPUT = "input";
//    String OUTPUT = "output";
//
//
//    pkiva.log.LogManager.getLogger(this.getClass()).debug("Getting LDAP connection: " + CONFIGPATH + CONNFACTORIES);
//    ConnectionFactory cxFactory = ServiceLocator.getInstance().getConnectionFactory(CONFIGPATH + CONNFACTORIES );
//
//    RecordFactory recordFactory = cxFactory.getRecordFactory();
//    IndexedRecord input = recordFactory.createIndexedRecord(INPUT);
//    input.clear();
//
//    IndexedRecord output = recordFactory.createIndexedRecord(OUTPUT);
//
//    LDAPInteractionSpec ispec =new LDAPInteractionSpecImpl();
//    ispec.setFunctionName(LDAPInteractionSpec.COLLECT_CAS_FUNCTION);
//
//    Connection connection = cxFactory.getConnection();
//    Interaction interaction = connection.createInteraction();
//
//    try
//    {
//      interaction.execute(ispec, input, output);
//    }
//    finally
//    {
//      // habria que hacer esto despues del record.get ??
//      interaction.close();
//      connection.close();
//    }
//
      return (Collection) JCAUtils.executeLDAP_RA_Function(LDAPJBDirContext.COLLECT_CAS_FUNCTION);
//    return (Collection) output.get(RESULT_FIELD);
  }
  
  protected Collection getDPsFromCAs( Collection cas ) //throws Exception
  {
    if ( cas == null )
      return Collections.EMPTY_SET;
    
    Vector idps = new Vector();
    
    Iterator caIter = cas.iterator();
    while ( caIter.hasNext() )
    {
      EstructuralElement el = (EstructuralElement) caIter.next();
      List dpList = el.getDistributionPoints();
      Iterator dpIter = dpList.iterator();
      while ( dpIter.hasNext() )
      {
        PKIXDistributionPoint pkixDP = (PKIXDistributionPoint) dpIter.next();
        if ( pkixDP.getType() == PKIXDistributionPoint.PKIXCRLDP )
        {
          String uri = pkixDP.getUri();
          String crlType = pkixDP.getCRLType();
          IssuingDistributionPoint idp = new IssuingDistributionPoint( uri, crlType );
          idp.setAttributes ( pkixDP.getAttributes() );
          idps.add( idp );
          
          // we could break here, but we'd better keep on looking for more DPs
        } // end if
      } // end while ( dpIter.hasNext() )
    } // end while ( caIter.hasNext() )
    
    return idps;
  }
  
  
  protected String translateOID ( String oid )
  {
    if ( oid == null )
      return null;

    else if ( "2.5.4.3".equals ( oid ) )
      return "CN";
    else if ( "2.5.4.6".equals ( oid ) )
      return "C";
    else if ( "2.5.4.10".equals ( oid ) )
      return "O";
    else if ( "2.5.4.11".equals ( oid ) )
      return "OU";

    else
      return oid;
  }

}
