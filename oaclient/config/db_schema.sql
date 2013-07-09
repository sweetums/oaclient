/*
** Author: Bill Mills
**
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
**
** DB scheme for the SQLite credential store database.
**
** XXXXXXX Need to sort out where we will actually put the database file.
*/


BEGIN;

CREATE TABLE IF NOT EXISTS creds (
	identity INTEGER NOT NULL,
	scheme NOT NULL,
	token  NOT NULL,
	secret,
	session,
	expiry INTEGER,
	PRIMARY KEY (identity, scheme),
	FOREIGN KEY (identity) REFERENCES identities (ROWID)
);

CREATE TABLE IF NOT EXISTS identities (
    	username,
    	realm,
    	scope,
    	authentication_url,
    	refresh_url,
    	initiate_url,
	PRIMARY KEY (username, realm, scope)
);

CREATE TABLE IF NOT EXISTS endpoints (
  	realm,
	username,
  	hostname,
  	port INTEGER,
  	path,
	identity INTEGER,
	PRIMARY KEY (username, hostname, port),
	FOREIGN KEY (identity) REFERENCES identities (ROWID)
);

CREATE TABLE IF NOT EXISTS config (
	name UNIQUE NOT NULL,
	value INTEGER,
	text,
	PRIMARY KEY (name)
);

REPLACE INTO config VALUES ('version', 0, '');

COMMIT;