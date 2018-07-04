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
package pkiva;


import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Vector;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import pkiva.utils.Log;
import pkiva.utils.PKIVAProperties;
import pkiva.webservices.exception.InternalValidatorException;
import pkiva.webservices.exception.ValidatorException;


/**
 * @author rnavalon
 */
public class CertificateFields {

	private String serialNumber;
	private int	   keyUsage;
	private String keyUsageAsString;
	private String policy;
	
	private Map subjectOids;
	private Map issuerOids;

	
	private Map oidMap( X509Name name ) {
		Map oids = new HashMap();
		String oidName  , oidValue;
		Vector oidNames , oidValues;
		int oidCount;
		
		oidNames = name.getOIDs();
		oidValues= name.getValues();
		oidCount = oidNames.size();

		Log.debug("Mapping " + oidCount + " OIDs");
		for( int i = 0; i < oidCount; i++ ) {
			oidName = oidNames.elementAt(i).toString();
			oidValue= oidValues.elementAt(i).toString();
			
			Log.debug("OID: " + oidName + " = " + oidValue);
			
			if ( oids.containsKey(oidName) ) {
				oidValue = (String)oids.get(oidName) + "\r" + oidValue;
			}
			
			oids.put( oidName , oidValue );
		}
		
		return oids;
	}
    
    private String getCertificateExtension( TBSCertificateStructure tbs , String extensionOid ) {
        String extension = null;
        
        try {
            ASN1OctetString ext = tbs.getExtensions().
                                   getExtension( new DERObjectIdentifier(extensionOid) )
                                   .getValue();
            
            Object o = new ASN1InputStream(ext.getOctets()).readObject();
            
            if ( o instanceof DERPrintableString ) {
                extension = ((DERPrintableString)o).getString();
            }
            
        } catch( Exception e ) { /* Ignore */ }
        
        return extension;
    }

	
	
	private void readFields( byte[] der ) throws InternalValidatorException {
		ASN1InputStream asn1is;
		X509CertificateStructure x509struct;
		TBSCertificateStructure tbs;
		X509Extension ext;

		asn1is = new ASN1InputStream( new ByteArrayInputStream(der) );

		try {
			x509struct = X509CertificateStructure.getInstance( asn1is.readObject() );
		} catch( IOException ioe ) {
			throw new InternalValidatorException(ioe);
		}
		
		tbs = x509struct.getTBSCertificate();


		// Serial number
		serialNumber = tbs.getSerialNumber().getValue().toString();
		
		
		// KeyUsage
		try {
			ext = tbs.getExtensions().getExtension( X509Extensions.KeyUsage );
			KeyUsage ku = new KeyUsage( (DERBitString)new ASN1InputStream(ext.getValue().getOctets()).readObject() );
			keyUsage = ku.intValue();
			
		} catch( Exception e ) {
			Log.warning("Error reading KeyUsage attribute from certificate", e );
		}
		
		StringBuffer sb = new StringBuffer(80);
		for( int bitTest = 0x8000; bitTest != 0; bitTest >>= 1 ) {
			if ( (keyUsage & bitTest) != 0 ) {
				if ( sb.length() != 0 ) sb.append(", ");
				switch( bitTest ) {
				case KeyUsage.decipherOnly: sb.append("decipherOnly"); break;
				case KeyUsage.digitalSignature: sb.append("digitalSignature"); break;
				case KeyUsage.nonRepudiation: sb.append("nonRepudiation"); break;
				case KeyUsage.keyEncipherment: sb.append("keyEncipherment"); break;
				case KeyUsage.dataEncipherment: sb.append("dataEncipherment"); break;
				case KeyUsage.keyAgreement: sb.append("keyAgreement"); break;
				case KeyUsage.keyCertSign: sb.append("keyCertSign"); break;
				case KeyUsage.cRLSign: sb.append("cRLSign"); break;
				case KeyUsage.encipherOnly: sb.append("encipherOnly"); break;
				}
			}
		}
		keyUsageAsString = sb.toString();
		
		
		// CertPolicy
		try {
			ext = tbs.getExtensions().getExtension( X509Extensions.CertificatePolicies );
			PolicyInformation policyInfo = new PolicyInformation((ASN1Sequence)((ASN1Sequence)new ASN1InputStream(ext.getValue().getOctets()).readObject()).getObjectAt(0));
			policy = policyInfo.getPolicyIdentifier().getId();
		} catch( Exception e ) {
			Log.warning("Error reading policies from certificate" , e );
		}

		
		
		/*
		 * ISSUER
		 */
        X509Name issuer = tbs.getIssuer();
        Log.debug("Issuer attributes...");
        issuerOids = oidMap(issuer);
        
        
		/*
		 * SUBJECT
		 */
        X509Name subject = tbs.getSubject();
        Log.debug("Subject attributes...");
        subjectOids = oidMap(subject);
	}

	
	
	
	
	public CertificateFields( X509Certificate cert ) throws ValidatorException {
		try {
			readFields( cert.getEncoded() );
			
		} catch( Exception e ) {
			throw new InternalValidatorException( e );
		}
	}
	
	public CertificateFields( byte[] der ) throws InternalValidatorException {
		try {
			readFields( der );
			
		} catch( Exception e ) {
			throw new InternalValidatorException( e );
		}
	}

	
	public String getSerialNumber() { return this.serialNumber; }
	public int    getKeyUsage() { return this.keyUsage; }
	public String getKeyUsageAsString() { return this.keyUsageAsString; }
	public String getPolicy() { return this.policy; }	
	public Map    getIssuerFields() { return this.issuerOids; }
	public Map    getSubjectFields() { return this.subjectOids; }
	
	public boolean isDigitalSignatureAllowed() { return (this.keyUsage & KeyUsage.digitalSignature) != 0; }
	
	public String toString() {
		StringBuffer sb = new StringBuffer(4096);
		
		sb.append("SerialNumber = ").append( getSerialNumber() ).append("\r\n");
		sb.append("KeyUsage = ").append( getKeyUsageAsString() ).append("\r\n");
		sb.append("Policy = ").append( getPolicy() ).append("\r\n");
		
		if ( getIssuerFields() != null )
			sb.append("Issuer fields = ").append( getIssuerFields().toString() ).append("\r\n");
		if ( getSubjectFields() != null )
			sb.append("Subject fields = ").append( getSubjectFields().toString() ).append("\r\n");
		
		return sb.toString();
	}
}
