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
package pkiva.log;

import java.util.Hashtable;
import java.util.Enumeration;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import javax.sql.DataSource;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import pkiva.exceptions.*;

/**
 * This class allows writing of audit messages to a database, using a DataSource.
 * 
 * DDL for database:
 *
 * CREATE TABLE PKI_VA_AUDIT
 * (
 * AUDIT_DATE     DATE default sysdate,
 * AUDIT_CHANNEL  VARCHAR2(256),
 * AUDIT_MESSAGE  VARCHAR2(2000)
 * )
 *
 * @author caller
 */
public class Auditer {
	/** Query to insert a message */    
	public static final String AUDIT_INSERT_QUERY = "insert into pki_va_audit(audit_date,audit_channel,audit_message) values(?,?,?)";
	/** Maximum size of audit_channel field. */    
	public static final int MAX_AUDIT_CHANNEL_SIZE = 256;
	/** Maximum size of messages audited */    
	public static final int MAX_AUDIT_MESSAGE_SIZE = 2000;
	/** DDL for table required to store messages. */    
	//public static final String DDL =  " CREATE TABLE PKI_VA_AUDIT ( AUDIT_DATE DATE default sysdate, AUDIT_CHANNEL VARCHAR2("+
	//MAX_AUDIT_CHANNEL_SIZE+"), AUDIT_MESSAGE  VARCHAR2("+MAX_AUDIT_MESSAGE_SIZE+") )";
	/** Datasource name to use */    
	public static String DS_NAME = "java:/EpsilonDS";
	
	
	// Nuevas Ago-04
	/** PKI_VA_AUDIT_REQUEST_TABLENAME */    
	public static final String PKI_VA_AUDIT_REQUEST_TABLENAME = "PKI_VA_AUDIT_REQUEST";
	
	/** PKI_VA_AUDIT_RESPONSE_TABLENAME */    
	public static final String PKI_VA_AUDIT_RESPONSE_TABLENAME = "PKI_VA_AUDIT_RESPONSE";
	
	/** PKI_VA_AUDIT_ENTRIES_TABLENAME */    
	public static final String PKI_VA_AUDIT_ENTRIES_TABLENAME = "PKI_VA_AUDIT_ENTRIES";
	
	/** QUERY FOR GETTING NEXT VALUE FROM SEQUENCE */    
	public static final String SEQUENCE_NEXT_VALUE_QUERY = "select SQ_PKI_VA_AUDIT_ENTRIES.nextval from dual";
	
	/** max size of varchar fields */
	public static final int VARCHAR_MAX_SIZE = 4000, BUFF_SIZE=256;
	
	/** Auditer name, often, the class name wich uses it. */    
	protected String name="";
	/** Datasource to get connections from. */    
	protected DataSource ds;
	/** Constructs an Auditer with given name.
	 * @param s Name of the created Auditer
	 */    
	public Auditer(String s) throws AuditingException
	{
		Context ctx=null;
		try{
			if(s.length()>MAX_AUDIT_CHANNEL_SIZE)
				name="..."+s.substring(s.length()-MAX_AUDIT_CHANNEL_SIZE+3,s.length());
			else
				name=s;
			ctx = new InitialContext();
			ds = (DataSource) ctx.lookup(DS_NAME);
		}
		catch (NamingException ne) {
			LogManager.getLogger(this.getClass()).error("Cannot resolve datasource name.",ne);
			throw new AuditingException ( "Cannot resolve datasource name.",ne );
		}
		finally{
			try{if(ctx!=null)ctx.close();}
			catch (NamingException ne){}
		}
	}
	
	/** Audits a message
	 * @param event Message to audit
	 * @param e Exception to store as well
	 */    
	public void audit(String event,Exception e) throws AuditingException
	{
		audit(new java.util.Date(),event,e);
	}
	/** Audits a message
	 * @param event Message to audit
	 */    
	public void audit(String event) throws AuditingException
	{
		audit(new java.util.Date(),event);
	}
	/** Audits a message
	 * @param d Date of the event being audited
	 * @param event Message to audit
	 * @param e Exception to store as well
	 */    
	public void audit(java.util.Date d,String event,Exception e) throws AuditingException
	{
		String message;
		if(event.length()>MAX_AUDIT_MESSAGE_SIZE)
			message = event.substring(0,MAX_AUDIT_MESSAGE_SIZE-6-e.getMessage().length())+"... - "+e.getMessage();
		else
			message = event;
		audit(d,message);
	}    
	
	/** Audits a message
	 * @param d Date of the event being audited
	 * @param event Message to audit
	 */    
	public void audit(java.util.Date d,String event) throws AuditingException
	{
		if(event.length()>MAX_AUDIT_MESSAGE_SIZE) {
			event = event.substring(0,MAX_AUDIT_MESSAGE_SIZE-3)+"...";
		}
		if(ds==null){
			LogManager.getLogger(this.getClass()).info("AUDIT: "+d+" : "+event);
			return;
		}
		Connection conn = null;
		PreparedStatement pStmt = null;
		try {
			conn = ds.getConnection();
			pStmt = conn.prepareStatement(AUDIT_INSERT_QUERY);
			pStmt.setTimestamp(1,new Timestamp(d.getTime()));
			pStmt.setString(2, name);
			pStmt.setString(3, event);
			pStmt.executeUpdate();
		}
		catch (SQLException sqle){
			LogManager.getLogger(this.getClass()).error("Exception inserting audit value: "+AUDIT_INSERT_QUERY, sqle);
			throw new AuditingException ( "Exception inserting audit value.",sqle);
		}
		finally {
			try {
				if (pStmt!=null) pStmt.close();
				if (conn!=null ) conn.close();
			}
			catch (SQLException sqle){}
		}
	}
	
	/** New way of auditing. Audits an AuditOperation
	 * @param oper AuditOperation to be audited
	 */    
	public void audit ( AuditOperation oper ) throws AuditingException
	{
		audit ( oper, new java.util.Date() );
	}
	
	/** New way of auditing. Audits an AuditOperation
	 * @param oper AuditOperation to be audited
	 * @param date operation date
	 */    
	public void audit ( AuditOperation oper, java.util.Date d ) throws AuditingException
	{
		int sequence = auditIncomplete ( oper, d );
		
		auditResponse ( oper, sequence );
	}
	
	/** Audits an AuditOperation, filling just the request fields.
	 * @param oper AuditOperation to be audited
	 */    
	public int auditIncomplete ( AuditOperation oper ) throws AuditingException
	{
		return auditIncomplete ( oper, new java.util.Date() ); 
	}
	
	/** Audits an AuditOperation, filling just the request fields.
	 * @param oper AuditOperation to be audited
	 * @param date operation date
	 */    
	public int auditIncomplete ( AuditOperation oper, java.util.Date d ) throws AuditingException
	{
		Timestamp date = new Timestamp( d.getTime() );
		
		int oper_id = oper.getOperation();
		
		int sequence = getSequence();
		
		sequence= insertEntry ( sequence, oper_id, date );
		
		insertRequest ( sequence, oper );
		
		return sequence;
	}
	
	/** Audits a previous incomplete audited AuditOperation, filling the response fields.
	 * @param oper AuditOperation to be audited
	 * @param entry_id Entry id got from previous incomplete audit
	 */    
	public void auditResponse ( AuditOperation oper, int entry_id ) throws AuditingException
	{
		insertResponse ( entry_id, oper );
	}
	
	private static final int INVALID_SEQ=-1;
	protected int getSequence ( ) throws AuditingException
	{
		int next = INVALID_SEQ;
		
		Connection conn = null;
		Statement stm = null;
		ResultSet rs = null;
		
		try
		{
			conn = ds.getConnection();
			stm = conn.createStatement();
			rs = stm.executeQuery( SEQUENCE_NEXT_VALUE_QUERY );
			
			if ( rs.next() )
			{
				next = rs.getInt(1);
			}
		}
		catch (SQLException sqle){
			next= INVALID_SEQ;
			//LogManager.getLogger(this.getClass()).warn("Exception getting next value from sequence."+sqle.getMessage()+" "+ SEQUENCE_NEXT_VALUE_QUERY);
			//Metodo solo valido para ORACLE 
			// En otros casos posteriormente se obtiene mediante statement.getGeneratedKeys()
			//throw new AuditingException ( "Exception getting next value from sequence.",sqle);
		}
		finally
		{
			try
			{rs.close();}
			catch (Exception e)
			{}
			try
			{stm.close();}
			catch (Exception e)
			{}
			try
			{conn.close();}
			catch (Exception e)
			{}
		}
		
		return next;
		
	}
	
	protected int insertEntry (final int sequence, final int oper_id, final Timestamp date ) throws AuditingException
	{
		int retSequence= sequence;
		StringBuffer querySB = new StringBuffer ( "insert into " );
		querySB.append ( PKI_VA_AUDIT_ENTRIES_TABLENAME );
		if (sequence!=INVALID_SEQ) {
			querySB.append ( " (ENTRY_ID, OPER_ID, OPER_DATE) values (?,?,?)" );
		} else {
			// AUTO_INCREMENT MODE
			querySB.append ( " (OPER_ID, OPER_DATE) values (?,?)" );
		}
		
		Connection conn = null;
		PreparedStatement pStmt = null;
		boolean autoCommitOldMode=true;

		try {
			conn = ds.getConnection();
			autoCommitOldMode= conn.getAutoCommit();
			// Init Transaction
			conn.setAutoCommit(false);
			
			pStmt = conn.prepareStatement(querySB.toString());
			int g=1;
			if (sequence!=INVALID_SEQ) {
				pStmt.setInt(g++,sequence);
			}
			pStmt.setInt(g++,oper_id );
			pStmt.setTimestamp(g++,date);
			pStmt.executeUpdate();
			
			// AUTO_INCREMENT MODE
			if (sequence==INVALID_SEQ) {
				ResultSet rsGK= null;
				try {
					rsGK= pStmt.getGeneratedKeys();
					if (rsGK!=null && rsGK.next()) {
						retSequence= rsGK.getInt(1);
					} else {
						LogManager.getLogger(this.getClass()).error("Exception obtaining audit ENTRY_ID value :"+querySB.toString());
						throw new AuditingException ( "Exception inserting audit value.");
					}
				} catch (SQLException se) {
					// ORACLE Error: Unsupported Feature ( http://www.oracle.com/technology/tech/java/sqlj_jdbc/htdocs/jdbc_faq.htm#02_04 )
					//	at oracle.jdbc.driver.DatabaseError.throwUnsupportedFeatureSqlException(DatabaseError.java:537)
					//	at oracle.jdbc.driver.OracleStatement.getGeneratedKeys(OracleStatement.java:4124)
					//	at org.jboss.resource.adapter.jdbc.WrappedStatement.getGeneratedKeys(WrappedStatement.java:500)
					LogManager.getLogger(this.getClass()).error("Unexpected SQL Error (getGeneratedKeys) ", se);
				} finally {
					if (rsGK!=null) {
						rsGK.close();
					}
				}
				
			}
			conn.commit();
		}
		catch (SQLException sqle){
			try {
				if (conn!=null) {
					conn.rollback();
				}
			} catch (SQLException e) {}
			
			LogManager.getLogger(this.getClass()).error("Exception inserting audit value."+querySB.toString(),sqle);
			throw new AuditingException ( "Exception inserting audit value.",sqle);
		}
		finally {
			try {
				if (pStmt!=null) {
					pStmt.close();
				}
				if (conn!=null) {
					conn.setAutoCommit(autoCommitOldMode);
					conn.close();
				}
			} catch (SQLException sqle){}
		}
		
		return retSequence;
	}
	
	protected void insertRequest (final int entry_id,final AuditOperation oper) throws AuditingException
	{
		insertInTable ( PKI_VA_AUDIT_REQUEST_TABLENAME, entry_id, oper.getRequest() );
	}
	
	protected void insertResponse (final int entry_id,final AuditOperation oper) throws AuditingException
	{
		insertInTable ( PKI_VA_AUDIT_RESPONSE_TABLENAME, entry_id, oper.getResponse() );
	}
	
	protected void insertInTable ( final String tableName, final int entry_id, final Hashtable params ) throws AuditingException
	{
		//LogManager.getLogger(this.getClass()).debug("inserting in table:params::" + params);
		final StringBuffer querySB = new StringBuffer ( "insert into " );
		
		// jcg20050530: OpenVA 
		//querySB.append ( tableName ).append ( " (ENTRY_ID, KEY_ID, VC_VALUE, BO_VALUE) values (?,?,?,EMPTY_BLOB())" );
		querySB.append ( tableName ).append ( " (ENTRY_ID, KEY_ID, VC_VALUE) values (?,?,?)" );
		
		Connection conn = null;
		PreparedStatement pStmt = null;
		try {
			conn = ds.getConnection();
			pStmt = conn.prepareStatement(querySB.toString());
			
			Enumeration keys = params.keys();
			while ( keys.hasMoreElements() )
			{
				Integer key_id = (Integer) keys.nextElement();
				AuditValue value = (AuditValue) params.get ( key_id );
				String vc_value = value.getAsVarchar();
				
				// diriarte: varchar longer than 4000 crashes db
				if ( (vc_value != null ) && (vc_value.length() > VARCHAR_MAX_SIZE) ) {
					vc_value = vc_value.substring(0, VARCHAR_MAX_SIZE - 3) + "...";
				}
				
				byte[] bo_value = value.getAsBlob();
				
				pStmt.setInt(1,entry_id);
				pStmt.setInt(2,key_id.intValue() );
				pStmt.setString(3,vc_value);
				pStmt.executeUpdate();
				
				if ( bo_value != null )
				{
					// jcg20050530: OpenVA
					final StringBuffer updSB= new StringBuffer("UPDATE ").append(tableName);
					updSB.append(" SET BO_VALUE = ? ");
					updSB.append ( " where ENTRY_ID = " ).append ( entry_id )
					.append ( " and KEY_ID = ").append (key_id.intValue());
					
					PreparedStatement ps=null;
					InputStream bfis= null; 
					try {
						ps= conn.prepareStatement( updSB.toString());

						// Insert the binary[] into the Blob
						bfis= new BufferedInputStream(new ByteArrayInputStream(bo_value), BUFF_SIZE);
						ps.setBinaryStream( 1, bfis, bo_value.length );
						
						LogManager.getLogger(this.getClass()).trace("Updating Blob size="+bo_value.length);
						// Execute the UPDATE
						int count = ps.executeUpdate();
						//LogManager.getLogger(this.getClass()).trace("Blob in "+tableName+" updated, entry_id="+entry_id+", key_id="+key_id.intValue());

					} catch (Exception e) {
						throw e;
					} finally {
						if (bfis!=null) bfis.close();
						if (ps!=null) ps.close();
					}
					
				} // end if bo_value != null
			} // end while
		}
		/*catch (IOException ioe){
		 LogManager.getLogger(this.getClass()).error("Exception inserting BLOB audit value.",ioe);
		 throw new AuditingException ( "Exception inserting BLOB audit value.",ioe);
		 }*/
		catch (Exception sqle){
			LogManager.getLogger(this.getClass()).error("Exception inserting audit value.",sqle);
			throw new AuditingException ( "Exception inserting audit value.",sqle);
		}
		finally {
			try {
				if (pStmt!=null) pStmt.close();
				if (conn!=null) conn.close();
			} catch (SQLException sqle){}
		}
	}
	
}
