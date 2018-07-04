CREATE SEQUENCE SQ_PKI_VA_AUDIT_ENTRIES
  START WITH 1
  MAXVALUE 100000000
  MINVALUE 1
  NOCYCLE
  CACHE 20
  NOORDER;

CREATE TABLE PKI_VA_AUDIT
(
  AUDIT_DATE     DATE                           DEFAULT sysdate,
  AUDIT_CHANNEL  VARCHAR2(256),
  AUDIT_MESSAGE  VARCHAR2(2000)
);

CREATE TABLE PKI_VA_AUDIT_ENTRIES
(
  ENTRY_ID   NUMBER(8)                          NOT NULL,
  OPER_ID    NUMBER(8)                          NOT NULL,
  OPER_DATE  DATE                               NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_KEYS
(
  KEY_ID      NUMBER(8)                         NOT NULL,
  KEY_NAME    VARCHAR2(255)                     NOT NULL,
  VALUE_TYPE  NUMBER(2)                         DEFAULT 0                     NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_OPERATIONS
(
  OPER_ID    NUMBER(8)                          NOT NULL,
  OPERATION  VARCHAR2(255)                      NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_OPERS_REQ_KEYS
(
  OPER_ID         NUMBER(8)                     NOT NULL,
  REQUEST_KEY_ID  NUMBER(8)                     NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_OPERS_RESP_KEYS
(
  OPER_ID          NUMBER(8)                    NOT NULL,
  RESPONSE_KEY_ID  NUMBER(8)                    NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_REQUEST
(
  ENTRY_ID  NUMBER(8)                           NOT NULL,
  KEY_ID    NUMBER(8)                           NOT NULL,
  VC_VALUE  VARCHAR2(4000),
  BO_VALUE  BLOB
);

CREATE TABLE PKI_VA_AUDIT_RESPONSE
(
  ENTRY_ID  NUMBER(8)                           NOT NULL,
  KEY_ID    NUMBER(8)                           NOT NULL,
  VC_VALUE  VARCHAR2(4000),
  BO_VALUE  BLOB
);

CREATE TABLE PKI_VA_AUDIT_STATES
(
  STATE_ID  NUMBER(8)                           NOT NULL,
  STATE     VARCHAR2(255)                       NOT NULL
);

CREATE TABLE PKI_VA_AUDIT_VAL_CHANNELS
(
  VC_ID  NUMBER(8)                              NOT NULL,
  VC     VARCHAR2(255)                          NOT NULL
);

CREATE TABLE PKI_VA_TRUSTSTORE
(
  BASE            VARCHAR2(255)                 NOT NULL,
  QUALIFIER       VARCHAR2(255),
  PRINCIPAL       VARCHAR2(255)                 NOT NULL,
  CREDENTIALS     VARCHAR2(255)                 NOT NULL,
  CREDENTIALTYPE  VARCHAR2(100),
  DPTYPE          VARCHAR2(100)
);

CREATE INDEX IDX_AUDIT_ENTRIES ON PKI_VA_AUDIT_ENTRIES
(OPER_DATE)
LOGGING
NOPARALLEL;

CREATE UNIQUE INDEX PK_AUDIT_ENTRIES ON PKI_VA_AUDIT_ENTRIES
(ENTRY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_KEYS ON PKI_VA_AUDIT_KEYS
(KEY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_OPERATIONS ON PKI_VA_AUDIT_OPERATIONS
(OPER_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_OPERS_REQUEST_KEYS ON PKI_VA_AUDIT_OPERS_REQ_KEYS
(OPER_ID, REQUEST_KEY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_OPERS_RESPONSE_KEYS ON PKI_VA_AUDIT_OPERS_RESP_KEYS
(OPER_ID, RESPONSE_KEY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_REQUEST ON PKI_VA_AUDIT_REQUEST
(ENTRY_ID, KEY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_RESPONSE ON PKI_VA_AUDIT_RESPONSE
(ENTRY_ID, KEY_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_STATES ON PKI_VA_AUDIT_STATES
(STATE_ID)
LOGGING
NOPARALLEL;


CREATE UNIQUE INDEX PK_AUDIT_VAL_CHANNELS ON PKI_VA_AUDIT_VAL_CHANNELS
(VC_ID)
LOGGING
NOPARALLEL;

ALTER TABLE PKI_VA_AUDIT_ENTRIES ADD (
  CONSTRAINT PK_AUDIT_ENTRIES
 PRIMARY KEY
 (ENTRY_ID));

ALTER TABLE PKI_VA_AUDIT_KEYS ADD (
  CONSTRAINT PK_AUDIT_KEYS
 PRIMARY KEY
 (KEY_ID));

ALTER TABLE PKI_VA_AUDIT_OPERATIONS ADD (
  CONSTRAINT PK_AUDIT_OPERATIONS
 PRIMARY KEY
 (OPER_ID));

ALTER TABLE PKI_VA_AUDIT_OPERS_REQ_KEYS ADD (
  CONSTRAINT PK_AUDIT_OPERS_REQUEST_KEYS
 PRIMARY KEY
 (OPER_ID, REQUEST_KEY_ID));

ALTER TABLE PKI_VA_AUDIT_OPERS_RESP_KEYS ADD (
  CONSTRAINT PK_AUDIT_OPERS_RESPONSE_KEYS
 PRIMARY KEY
 (OPER_ID, RESPONSE_KEY_ID));

ALTER TABLE PKI_VA_AUDIT_REQUEST ADD (
  CONSTRAINT PK_AUDIT_REQUEST
 PRIMARY KEY
 (ENTRY_ID, KEY_ID));

ALTER TABLE PKI_VA_AUDIT_RESPONSE ADD (
  CONSTRAINT PK_AUDIT_RESPONSE
 PRIMARY KEY
 (ENTRY_ID, KEY_ID));

ALTER TABLE PKI_VA_AUDIT_STATES ADD (
  CONSTRAINT PK_AUDIT_STATES
 PRIMARY KEY
 (STATE_ID));

ALTER TABLE PKI_VA_AUDIT_VAL_CHANNELS ADD (
  CONSTRAINT PK_AUDIT_VAL_CHANNELS
 PRIMARY KEY
 (VC_ID));

ALTER TABLE PKI_VA_AUDIT_ENTRIES ADD (
  CONSTRAINT FK_ENTRIES_OPERATIONS 
 FOREIGN KEY (OPER_ID) 
 REFERENCES PKI_VA_AUDIT_OPERATIONS (OPER_ID));

ALTER TABLE PKI_VA_AUDIT_OPERS_REQ_KEYS ADD (
  CONSTRAINT FK_OPERS_REQ_KEYS_KEYS 
 FOREIGN KEY (REQUEST_KEY_ID) 
 REFERENCES PKI_VA_AUDIT_KEYS (KEY_ID),
  CONSTRAINT FK_OPERS_REQ_KEYS_OPERATIONS 
 FOREIGN KEY (OPER_ID) 
 REFERENCES PKI_VA_AUDIT_OPERATIONS (OPER_ID));

ALTER TABLE PKI_VA_AUDIT_OPERS_RESP_KEYS ADD (
  CONSTRAINT FK_OPERS_RES_KEYS_KEYS 
 FOREIGN KEY (RESPONSE_KEY_ID) 
 REFERENCES PKI_VA_AUDIT_KEYS (KEY_ID),
  CONSTRAINT FK_OPERS_RES_KEYS_OPERATIONS 
 FOREIGN KEY (OPER_ID) 
 REFERENCES PKI_VA_AUDIT_OPERATIONS (OPER_ID));

ALTER TABLE PKI_VA_AUDIT_REQUEST ADD (
  CONSTRAINT FK_REQUEST_ENTRIES 
 FOREIGN KEY (ENTRY_ID) 
 REFERENCES PKI_VA_AUDIT_ENTRIES (ENTRY_ID),
  CONSTRAINT FK_REQUEST_KEYS 
 FOREIGN KEY (KEY_ID) 
 REFERENCES PKI_VA_AUDIT_KEYS (KEY_ID));

ALTER TABLE PKI_VA_AUDIT_RESPONSE ADD (
  CONSTRAINT FK_RESPONSE_ENTRIES 
 FOREIGN KEY (ENTRY_ID) 
 REFERENCES PKI_VA_AUDIT_ENTRIES (ENTRY_ID),
  CONSTRAINT FK_RESPONSE_KEYS 
 FOREIGN KEY (KEY_ID) 
 REFERENCES PKI_VA_AUDIT_KEYS (KEY_ID));

GRANT ALTER, DELETE, INDEX, INSERT, REFERENCES, SELECT, UPDATE ON  PKI_VA_AUDIT TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_ENTRIES TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_KEYS TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_OPERATIONS TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_OPERS_REQ_KEYS TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_OPERS_RESP_KEYS TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_REQUEST TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_RESPONSE TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_STATES TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_AUDIT_VAL_CHANNELS TO EPSILON;

GRANT DELETE, INSERT, SELECT, UPDATE ON  PKI_VA_TRUSTSTORE TO EPSILON;

GRANT SELECT ON  SQ_PKI_VA_AUDIT_ENTRIES TO EPSILON;

INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
1, 'CERT_ISSUER', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
2, 'CERT_SUBJECT', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
3, 'CERT_SERIAL_NUMBER', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
4, 'CERT_FINGERPRINT', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
5, 'POLICIES', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
6, 'VALIDATION_CHANNEL', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
7, 'VALIDATION_STATE', 1); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
8, 'REVOCATION_OBJECT', 2); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
9, 'POLICY_TREE', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
10, 'TRUST_ANCHOR_SUBJECT', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
11, 'TRUST_ANCHOR_SERIAL_NUMBER', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
12, 'TRUST_ANCHOR_FINGERPRINT', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
13, 'DATA_EXTRACTION_PATH', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
14, 'DATA_EXTRACTION_ITEM', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
15, 'URL', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
16, 'CRL', 2); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
17, 'SUCCESS', 3); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
99, 'INTERNAL_ERROR', 0); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
20, 'DIGEST', 2); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
19, 'CONTENT', 2); 
INSERT INTO PKI_VA_AUDIT_KEYS ( KEY_ID, KEY_NAME, VALUE_TYPE ) VALUES ( 
18, 'PKCS7', 2); 

INSERT INTO PKI_VA_AUDIT_OPERATIONS ( OPER_ID, OPERATION ) VALUES ( 
1, 'CERTIFICATE_VALIDATION'); 
INSERT INTO PKI_VA_AUDIT_OPERATIONS ( OPER_ID, OPERATION ) VALUES ( 
2, 'CERTIFICATE_DATA_EXTRACTION'); 
INSERT INTO PKI_VA_AUDIT_OPERATIONS ( OPER_ID, OPERATION ) VALUES ( 
3, 'CRL_INSTALL'); 
INSERT INTO PKI_VA_AUDIT_OPERATIONS ( OPER_ID, OPERATION ) VALUES ( 
4, 'LDAP_LOAD'); 
INSERT INTO PKI_VA_AUDIT_OPERATIONS ( OPER_ID, OPERATION ) VALUES ( 
5, 'SIGNATURE_VALIDATION'); 


INSERT INTO PKI_VA_AUDIT_STATES ( STATE_ID, STATE ) VALUES ( 
1, 'OK'); 
INSERT INTO PKI_VA_AUDIT_STATES ( STATE_ID, STATE ) VALUES ( 
2, 'REVOKED'); 
INSERT INTO PKI_VA_AUDIT_STATES ( STATE_ID, STATE ) VALUES ( 
3, 'UNKNOWN'); 

INSERT INTO PKI_VA_AUDIT_VAL_CHANNELS ( VC_ID, VC ) VALUES ( 
1, 'CRL'); 
INSERT INTO PKI_VA_AUDIT_VAL_CHANNELS ( VC_ID, VC ) VALUES ( 
2, 'OCSP'); 


COMMIT;
