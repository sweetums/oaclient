/*
** Author: Bill Mills
** Copyright Yahoo! Inc., 2011
**
** DB scheme for the SQLite credential store database.
**
** XXXXXXX Need to sort out where we will actually put the database file.
*/


BEGIN;

DROP TABLE IF EXISTS creds;
DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS endpoints;

COMMIT;