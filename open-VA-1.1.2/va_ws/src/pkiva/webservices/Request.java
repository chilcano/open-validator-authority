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
package pkiva.webservices;

import org.w3c.dom.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import java.io.ByteArrayInputStream;

import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CertSelector;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformation;

import pkiva.webservices.exception.InternalValidatorException;




/**
 * @author rnavalon
 */
public class Request {

	public static final int UNDEFINED			= -1;
	public static final int RAWX509CERTIFICATE	= 1;
	public static final int PKCS7SIGNATURE		= 2;
	public static final int SIGNEDDETACHEDDOC	= 3;
	
	
	private Element request;
	
	
	
	private Element child( Element parent , String childName ) throws InternalValidatorException {
		NodeList children;
		
		children = parent.getElementsByTagName(childName);
		
		if ( children == null || children.getLength() == 0 ) {
			return null;
		}
		
		if ( children.getLength() != 1 ) {
			throw new InternalValidatorException( "Only one " + childName + " node is allowed" );
		}
		
		return (Element)children.item(0);
	}
	
	private Element[] children( Element parent ) throws InternalValidatorException {
		Element[] childNodes = null;
		NodeList nodes;
		List alist = new ArrayList();
		
		nodes = parent.getChildNodes();
		
		for( int n = 0; n < nodes.getLength(); n++ ) {
			if ( nodes.item(n).getNodeType() == Node.ELEMENT_NODE ) {
				alist.add( nodes.item(n) );
			}
		}
		
		if ( alist.size() != 0 ) {
			childNodes = new Element[alist.size()];
			
			int n;
			Iterator it;
			for( it = alist.iterator() , n = 0; it.hasNext(); n++ ) {
				childNodes[n] = (Element)it.next();
			}
		}
		
		return childNodes;
	}
	
	private String textValue( Element element ) {
		String value = null;
		Node childNode;
		
		childNode = element.getFirstChild();
		if ( childNode.getNodeType() == Node.TEXT_NODE || childNode.getNodeType() == Node.CDATA_SECTION_NODE ) {
			value = childNode.getNodeValue();
		}
		
		return value;
	}
	
	private byte[] rawValue( Element element ) {
		byte[] raw = null;
		String text;
		
		if ( (text = textValue(element)) != null ) {
			raw = Base64.decode( text.trim().getBytes() );
		}
		
		return raw;
	}
	
	private X509Certificate certificateFromRaw( byte[] raw ) throws InternalValidatorException {
		X509Certificate cert = null;
		
		try {
			CertificateFactory cf;
			ByteArrayInputStream bais;
					
			cf = CertificateFactory.getInstance("X.509");
					
			bais = new ByteArrayInputStream( raw );
			cert = (X509Certificate)cf.generateCertificate( bais );
			bais.close();
			
		} catch( Exception e ) {
			throw new InternalValidatorException( e );
		}
		
		return cert;
	}
	
	private X509Certificate certificateFromPKCS7( byte[] pkcs7 ) throws InternalValidatorException {
		X509Certificate cert = null;
		
		try {
			CMSSignedData signedData = new CMSSignedData (pkcs7);
			CertStore     certs      = signedData.getCertificatesAndCRLs("Collection", "BC");
			CertSelector  certSelector = null;
        
			SignerInformationStore  signers = signedData.getSignerInfos();
			Collection              c       = signers.getSigners();
			Iterator                it      = c.iterator();

			SignerInformation signer = (SignerInformation)it.next();
			certSelector = signer.getSID();
			Collection certCollection = certs.getCertificates(certSelector);
			
			if ( ( certCollection != null ) && ( !certCollection.isEmpty()) )
				cert = (X509Certificate)certCollection.toArray(new X509Certificate[0])[0];

		} catch( Exception e ) {
			throw new InternalValidatorException( e );
		}
		
		return cert;
	}
	
	
	
	
	public Request( String xmlIn ) throws InternalValidatorException {
		try {
			DocumentBuilderFactory dbf;
			DocumentBuilder db;
			Document doc;
		
			dbf = DocumentBuilderFactory.newInstance();
			db  = dbf.newDocumentBuilder();
		
			ByteArrayInputStream bais = new ByteArrayInputStream( xmlIn.getBytes() );
			doc = db.parse( bais );
			bais.close();
			
			this.request = doc.getDocumentElement();
			
		} catch( Exception e ) {
			throw new InternalValidatorException( e );
		}
	}
	
	
	public int getOption() throws InternalValidatorException {
		Element elementId;
		String elementIdValue;
		
		elementId = child(request, "elementId");
		elementIdValue = textValue( elementId );
		
		if ( elementIdValue.equals("RawX509Certificate") ) {
			return RAWX509CERTIFICATE;
		} else if ( elementIdValue.equals("PKCS7Signature") ) {
			return PKCS7SIGNATURE;
		} else if ( elementIdValue.equals("SignedDetDoc") ) {
			return SIGNEDDETACHEDDOC;
		} else if ( elementIdValue == null ) {
			throw new InternalValidatorException( "Expected elementId node" );
		} else {
			return UNDEFINED;
		}
	}
	
	public byte[] getRawCertificate() throws InternalValidatorException {
		byte[] raw = null;
		Element elementContent;
		Element certificate;
		
		elementContent = child(request, "elementContent");
		certificate = child(elementContent, "certificate");
		
		if ( certificate != null ) {
			raw = rawValue(certificate);
		}
		
		return raw;
	}
	
	public byte[] getRawSignedDocument() throws InternalValidatorException {
		byte[] raw = null;
		Element elementContent;
		Element signedDoc;
		
		elementContent = child(request, "elementContent");
		signedDoc = child(elementContent, "signedDoc");
		if ( signedDoc != null ) {
			raw = rawValue( signedDoc );
		}
		
		return raw;
	}
	
	public byte[] getRawSignature() throws InternalValidatorException {
		byte[] raw = null;
		Element elementContent;
		Element signature;
		
		elementContent = child(request, "elementContent");
		signature = child(elementContent, "signature");
		
		if ( signature != null ) {
			raw = rawValue( signature );
		}
		
		return raw;
	}

	public byte[] getRawDocument() throws InternalValidatorException {
		byte[] raw = null;
		Element elementContent;
		Element doc;
		
		elementContent = child(request, "elementContent");
		doc = child(elementContent, "doc");
		
		if ( doc != null ) {
			raw = rawValue( doc );
		}
		
		return raw;
	}
	
	public boolean isFields() throws InternalValidatorException {
		Element fields;
		
		fields = child(request, "fields");
		
		return fields != null;
	}
	
	
	public X509Certificate getCertificate() throws InternalValidatorException {
		switch( getOption() ) {
		case RAWX509CERTIFICATE:
			return certificateFromRaw( getRawCertificate() );
			
		case PKCS7SIGNATURE:
			return certificateFromPKCS7( getRawSignedDocument() );
			
		case SIGNEDDETACHEDDOC:
			return certificateFromPKCS7( getRawSignature() );
			
			default:
				throw new InternalValidatorException("Option not supported");
		}
	}
}
