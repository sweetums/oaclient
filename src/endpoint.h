/* Oauth SASL plugin
 * Bill Mills, Tim Showalter
 * $Id:  $
 */
/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#ifndef INCLUDED_ENDPOINT_H
#define INCLUDED_ENDPOINT_H

#include "../include/oaclient.h"

struct oaclient_endpoint
{
  char *username;
  char *hostname;
  oac_u32 port;
  char *path;
  unsigned int rowid;
};

/*
 * oaclient_endpoint_isCached
 *
 * Checks the cache to see if the endpoint is cached.  If so, puts the ROWID
 * into the struct for later use.
 */
int oaclient_endpoint_isCached(struct oaclient_ctx *ctx, struct oaclient_endpoint *ep);

int oaclient_endpoint_get_rowid(struct oaclient_endpoint *ep);
void oaclient_endpoint_set_rowid(struct oaclient_endpoint *ep, unsigned int rowid);

#endif
