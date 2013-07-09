# Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# See accompanying LICENSE file for terms.
#
#
CC=gcc
# CFLAGS=-g -Wall -I ../src -I../include -L/usr/lib -lcurl -L/usr/local/lib -loauth -ljansson
CFLAGS=-g -Wall -I../src -L../src -I../include -L/lib -L/usr/lib -lcurl -L/usr/local/lib -loauth -ljansson
ALL=oa-util

CRUFT=oaclient_store.db

OA_UTIL_OBJS=oa-util.o 

TESTS=

COMMON_OBJS=

OBJS=$(COMMON_OBJS) $(OA_UTIL_OBJS)


all: $(ALL) clean-db


oa-util: $(COMMON_OBJS) $(OA_UTIL_OBJS) liboaclient.a
	$(CC) $(CFLAGS) -o $@ $(COMMON_OBJS) $(OA_UTIL_OBJS) -lsqlite3 -loaclient



liboaclient.a:
	cd ../src && $(MAKE)


clean: clean-db
	rm -f $(ALL) $(OBJS) || true
	rm -f *~ || true

clean-db:
	!(test -e $(CRUFT)) || rm $(CRUFT)
