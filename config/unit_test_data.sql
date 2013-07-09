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
*/


BEGIN;

INSERT INTO identities VALUES ('user@example.com', 'example.com', 
	'demo', 'http://login.example.com/',  
	'http://login.example.com/token',
 	'http://login.example.com/init');

INSERT INTO creds VALUES (
	(SELECT ROWID FROM identities WHERE username == 'user@example.com' LIMIT 1), 
	'bearer', 'token_goes_here',  'i_am_a_secret',  'jam_session', 3600);

INSERT INTO endpoints VALUES (
	'example.com', 'user@example.com', 'imap.example.com', 143,  '', 
	(SELECT ROWID FROM identities WHERE username == 'user@example.com' LIMIT 1)
	);

COMMIT;