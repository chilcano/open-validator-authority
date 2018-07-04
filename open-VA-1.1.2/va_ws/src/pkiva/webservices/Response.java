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

import java.io.ByteArrayOutputStream;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

import org.w3c.dom.*;

import org.bouncycastle.cms.*;
import org.bouncycastle.util.encoders.Base64;

import pkiva.CertificateFields;
import pkiva.utils.PKIVAProperties;
import pkiva.webservices.exception.InternalValidatorException;

/**
 * @author rnavalon
 */
public class Response {
	
	public static final int UNDEFINED = -1;
	
	public static final int SUCCESS = 0;
	public static final int FAILURE = 1;
	public static final int REFUSED	= 2;
	
	public static final int VALID	= 0;
	public static final int INVALID	= 1;
	
	
	private int    value 		= UNDEFINED;
	private String codeError;
	private int    status		= UNDEFINED;
	private int    statusReason;
	private String statusReasonDescription;
	private CertificateFields fields;
	

	private static String valueToString( int value ) {
		switch( value ) {
		case SUCCESS: return "Success";
		case FAILURE: return "Failure";
		case REFUSED: return "Refused";
		default:
			return "Undefined";
		}
	}
	
	private static String statusToString( int status ) {
		switch( status ) {
		case VALID: return "Valid";
		case INVALID: return "Invalid";
		default:
			return "Undefined";
		}
	}
	
	
	
	private Element createChild( Element parent , String name ) {
		Element child;
		Document doc = parent.getOwnerDocument();
		
		child = doc.createElement(name);
		parent.appendChild( child );
		
		return child;
	}
	
	private Element createTextChild( Element parent , String name , String value ) {
		Element child;
		Node    valueNode;
		Document doc = parent.getOwnerDocument();
		
		child = createChild(parent,name);
		if ( value != null ) {
			valueNode = doc.createTextNode( value );
			child.appendChild( valueNode );
		}
		
		return child;
	}
	
	private Element createDataChild( Element parent , String name , Object value ) {
		Element child;
		Node    valueNode;
		Document doc = parent.getOwnerDocument();
		
		child = createChild(parent,name);
		if ( value != null ) {
			valueNode = doc.createCDATASection( value.toString() );
			child.appendChild( valueNode );
		}
		
		return child;
	}
	
	
	
	private String sign( byte[] data ) throws InternalValidatorException {	
		try {
			PrivateKey prvKey; 
			X509Certificate[] certChain;

			prvKey = SignatureData.getPrivateKey();
			certChain = SignatureData.getCertificateChain();
		
			CMSProcessable msg = new CMSProcessableByteArray(data);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			gen.addSigner(prvKey, SignatureData.getEECertificate(certChain), SignatureData.getAlgorithm() );

			gen.addCertificatesAndCRLs(SignatureData.getAllCertificates(certChain));

			CMSSignedData s = gen.generate(msg, true, "BC");

			return new String(Base64.encode(s.getEncoded()));
			
		} catch( InternalValidatorException ive ) {
			throw ive;
		} catch(Exception e) {
			throw new InternalValidatorException(e);
		}		
	}

	
	
	
	protected String serialize(Document doc) throws InternalValidatorException {
		ByteArrayOutputStream baos;
		DOMSource source;
		StreamResult result;

		baos   = new ByteArrayOutputStream();
		source = new DOMSource(doc);
		result = new StreamResult(baos);

		TransformerFactory transFactory = TransformerFactory.newInstance();
		Transformer transformer;
		
		try {
			String encoding = PKIVAProperties.getProperty("pkiva.output.encoding","ISO-8859-1");
			
			transformer = transFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.ENCODING, encoding);
			transformer.transform(source, result);
			
		} catch(Exception e) {
			throw new InternalValidatorException(e);
		}
		
		return baos.toString();
	}	
	
	
	
	
	public int getValue() { return this.value; }
	public void setValue( int value ) { this.value = value; }
	
	public String getCodeError() { return this.codeError; }
	public void setCodeError( String codeError ) { this.codeError = codeError; }
	
	public int getStatus() { return this.status; }
	public void setStatus( int status ) { this.status = status; }
	
	public int getStatusReason() { return this.statusReason; }
	public void setStatusReason( int statusReason ) { this.statusReason = statusReason; }
	
	public String getStatusReasonDescription() { return this.statusReasonDescription; }
	public void setStatusReasonDescription( String statusReasonDescription ) { this.statusReasonDescription = statusReasonDescription; }
	
	public CertificateFields getFields() { return this.fields; }
	public void setFields( CertificateFields fields ) { this.fields = fields; }

	
	
	
	
	public Document toXML() throws InternalValidatorException {
		try {
			DocumentBuilderFactory dbf;
			DocumentBuilder db;
			DOMImplementation di;
			
			Document doc;
			Element  response;
			
			
			dbf = DocumentBuilderFactory.newInstance();
			db  = dbf.newDocumentBuilder();
			di  = db.getDOMImplementation();
			doc = di.createDocument("","response",null);
			response = doc.getDocumentElement();
		

			createTextChild(response,"value", valueToString(value));
			if ( codeError != null ) {
				createTextChild(response,"codeError", codeError);
			}
			
			createTextChild(response,"status", statusToString(status));
			if ( statusReason != 0 ) {
				StringBuffer msgStatusReason = new StringBuffer(256);
				
				msgStatusReason.append( statusReason );
				msgStatusReason.append( ':' );
				msgStatusReason.append( PKIVAProperties.getProperty( "error." + statusReason , "Error " + statusReason ) );
				
				createTextChild(response,"statusReason", msgStatusReason.toString());
			}

			if ( fields != null ) {
				Element fieldsNode = createChild( response , "fields" );
				
				createTextChild(fieldsNode, "serialNumber", fields.getSerialNumber() );
				createTextChild(fieldsNode, "keyUsage", fields.getKeyUsageAsString() );
				createTextChild(fieldsNode, "policy", fields.getPolicy() );
				
				Map issuerFields = fields.getIssuerFields();
				if ( issuerFields != null && issuerFields.size() > 0 ) {
					Element issuerFieldsNode = createChild(fieldsNode,"issuer");
					
					for( Iterator it = issuerFields.keySet().iterator(); it.hasNext(); ) {
						String oidName = (String)it.next();
						Object oidValue= (String)issuerFields.get(oidName);
						
						if ( oidValue != null ) {
							Element fieldNode;
							
							fieldNode = createDataChild(issuerFieldsNode, "oid", oidValue);
							fieldNode.setAttribute("name", oidName);
						}
					}
				}
				
				Map subjectFields = fields.getSubjectFields();
				if ( subjectFields != null && subjectFields.size() > 0 ) {
					Element subjectFieldsNode = createChild(fieldsNode,"subject");
					
					for( Iterator it = subjectFields.keySet().iterator(); it.hasNext(); ) {
						String oidName = (String)it.next();
						Object oidValue= (String)subjectFields.get(oidName);
						
						if ( oidValue != null ) {
							Element fieldNode;
							
							fieldNode = createDataChild(subjectFieldsNode, "oid",oidValue);
							fieldNode.setAttribute("name", oidName);
						}
					}
				}				
			}
				

			createTextChild( response , "signature" , sign(serialize(doc).getBytes()) );
			
			return doc;
			
		} catch( InternalValidatorException ive ) {
			throw ive;
		} catch( Exception e ) {
			throw new InternalValidatorException(e);
		}
	}
	
	
	public String toString() {
		StringBuffer sb = new StringBuffer(80);
		
		sb.append( "value = " );
		sb.append( valueToString(value) );
		if ( codeError != null ) {
			sb.append( " codeError = " );
			sb.append( codeError );
		}
		
		sb.append( " status = " );
		sb.append( statusToString(status) );
		if ( statusReason != 0 ) {
			sb.append( " statusReason = " );
			sb.append( statusReason );
		}
		
		return sb.toString();
	}
	
	public String toXMLString() throws InternalValidatorException {
		return serialize( toXML() );
	}
}
