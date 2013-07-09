#
# Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# See accompanying LICENSE file for terms.
#

OACLIENT_LIB=../.libs/liboaclient.so
CC=gcc
CFLAGS=-g -Wall -I ../ -I../../include -L/usr/lib -lcurl -L/usr/local/lib -loauth -ljansson
ALL=unit-tunnel unit-endpoint unit-identity unit-credential unit-ctx unit-sql_db $(OACLIENT_LIB)

CRUFT=oaclient_store.db

UNIT_ENDPOINT_OBJS=unit-endpoint.o 
UNIT_IDENTITY_OBJS=unit-identity.o 
UNIT_CREDENTIAL_OBJS=unit-credential.o 
UNIT_TUNNEL_OBJS=unit-tunnel.o 
UNIT_CTX_OBJS=unit-ctx.o 
UNIT_SQL_DB_OBJS=unit-sql_db.o 

TESTS=unit-endpoint unit-identity unit-credential unit-tunnel unit-ctx

COMMON_OBJS=unit_test_utils.o

OBJS=$(COMMON_OBJS) $(UNIT_TUNNEL_OBJS) $(UNIT_ENDPOINT_OBJS) $(UNIT_IDENTITY_OBJS) $(UNIT_CREDENTIAL_OBJS) $(UNIT_CTX_OBJS)  $(UNIT_SQL_DB_OBJS)


all: $(ALL) clean-db

run: $(TESTS)
	for t in $(TESTS) ; do \
		./$${t} ; \
	done

unit-endpoint: $(COMMON_OBJS) $(UNIT_ENDPOINT_OBJS) $(OACLIENT_LIB)
	$(CC) $(CFLAGS) -o $@ $^ -lsqlite3

unit-identity: $(COMMON_OBJS) $(UNIT_IDENTITY_OBJS) $(OACLIENT_LIB)
	$(CC) $(CFLAGS) -o $@ $^  -lsqlite3

unit-credential: $(COMMON_OBJS) $(UNIT_CREDENTIAL_OBJS) $(OACLIENT_LIB)
	$(CC) $(CFLAGS) -o $@ $^  -lsqlite3

unit-tunnel: $(COMMON_OBJS) $(UNIT_TUNNEL_OBJS) $(OACLIENT_LIB)
	$(CC) $(CFLAGS) -o $@ $^ -lsqlite3

unit-ctx: $(COMMON_OBJS) $(UNIT_CTX_OBJS) $(OACLIENT_LIB)
	$(CC) $(CFLAGS) -o $@ $^  -lsqlite3

unit-sql_db:  $(UNIT_SQL_DB_OBJS)  $(COMMON_OBJS) 
	$(CC) $(CFLAGS) -o $@ $^ -lsqlite3  $(OACLIENT_LIB)


$(OACLIENT_LIB):
	cd .. && $(MAKE) liboaclient.la



clean: clean-db
	rm -f $(ALL) $(OBJS) || true
	rm -f *~ || true

clean-db:
	rm -f $(CRUFT)  || true
