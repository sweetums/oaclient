#
# Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# See accompanying LICENSE file for terms.
#


SUBDIRS = src sample

.PHONY: subdirs $(SUBDIRS) clean all

subdirs all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)

sample: src

clean: 
	TARGET=$@ $(MAKE) 
