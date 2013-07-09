#
# Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# See accompanying LICENSE file for terms.
#

prefix = /usr/local
exec_prefix = ${prefix}
plugindir = /usr/local/lib

sysconfdir = ${prefix}/etc
target = i686-pc-linux-gnu
target_alias =
target_cpu = i686
target_os = linux-gnu
target_vendor = pc


DESTDIR = $(plugindir)

INSTALL = /usr/bin/install -c
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
PRE_INSTALL = :
POST_INSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = ${SHELL} $(install_sh) -c -s
# install_sh = /homes/wmills/sasl/cyrus-sasl-2.1.23/config/install-sh

installable_LTLIBRARIES=liboaclient.la


SHELL = /bin/sh

DEPDIR = .deps
# LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBTOOL = $(SHELL) /usr/bin/libtool
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) \
	$(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

CCLD = $(CC)
AM_LDFLAGS = -module -export-dynamic -rpath $(plugindir)
LDFLAGS =
CC=gcc
CFLAGS=-g -Wall -Wimplicit -I../include
#CFLAGS = -Wall -W -g -O2

LINK = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
        $(AM_LDFLAGS) $(LDFLAGS) -o $@

COMMOM_SOURCES=../include/oaclient.h accessor.h
SUBDIRS=tests
DYNAMIC_OBJS=sql_commands.h

# ALL=liboaclient.a  sql_commands.h $(SUBDIRS)
ALL=$(SUBDIRS)
SOURCES=ctx.c credential.c identity.c endpoint.c tunnel.c sql_db.c
OBJS=ctx.o credential.o identity.o endpoint.o tunnel.o sql_db.o

CONFIGDIR=../config

liboaclient_la_OBJECTS = ctx.lo credential.lo identity.lo endpoint.lo tunnel.lo sql_db.lo
liboaclient_la_SOURCES = $(SOURCES) $(common_sources)
#liboaclient_la_LDFLAGS = -version-info $(oauth_version)
liboaclient_la_LDFLAGS = 
liboaclient_la_DEPENDENCIES = $(COMPAT_OBJS)
liboaclient_la_LIBADD =  -lcrypt -ljansson -lsqlite3 -loauth  -lcurl 


#all: sql_commands.h liboaclient.la liboaclient.a $(ALL)
all: sql_commands.h liboaclient.la $(ALL)

#credential.lo: credential.c credential.h $(COMMON_SOURCES)

#ctx.lo: ctx.c ctx.h $(COMMON_SOURCES)

# endpoint.lo endpoint.lo: endpoint.c endpoint.h $(COMMON_SOURCES)

#identity.lo: identity.c identity.h $(COMMON_SOURCES)

#sql_db.lo: sql_db.c sql_db.h $(COMMON_SOURCES)

#tunnel.lo: tunnel.c tunnel.h $(COMMON_SOURCES)


#liboaclient.a: $(OBJS) $(DYNAMIC_OBJS)
#	ar r $@ $?

liboaclient.la: $(liboaclient_la_OBJECTS) $(liboaclient_la_DEPENDENCIES) 
	$(LINK)  $(liboaclient_la_LDFLAGS) $(liboaclient_la_OBJECTS) $(liboaclient_la_LIBADD) $(LIBS)

sql_commands.h: import_sql.sh $(wildcard $(CONFIGDIR)/*.sql)
	$(MAKE) clean
	/bin/sh import_sql.sh $@
	$(MAKE) all

clean:
	rm -f $(ALL) $(OBJS) || true
	rm -f *~ || true

tests:
	cd unit-tests && $(MAKE)

%.lo: %.c $(DEPDIR)
	if $(LTCOMPILE) -MT $@ -MD -MP -MF "$(DEPDIR)/$*.Tpo" \
	  -c -o $@ `test -f '$<' || echo '$(srcdir)/'`$<; \
	then mv -f "$(DEPDIR)/$*.Tpo" "$(DEPDIR)/$*.Plo"; \
	else rm -f "$(DEPDIR)/$*.Tpo"; exit 1; \
	fi

$(DEPDIR): 
	mkdir $(DEPDIR)

saslLTLIBRARIES_INSTALL = $(INSTALL)

install: $(installable_LTLIBRARIES)
	test -d $(DESTDIR)
	@list='$(installable_LTLIBRARIES)'; for p in $$list; do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    echo " $(LIBTOOL) --mode=install $(saslLTLIBRARIES_INSTALL) $(INSTALL_STRIP_FLAG) $$p $(DESTDIR)/$$f"; \
	    $(LIBTOOL) --mode=install $(saslLTLIBRARIES_INSTALL) $(INSTALL_STRIP_FLAG) $$p $(DESTDIR)/$$f; \
	  else :; fi; \
	done

