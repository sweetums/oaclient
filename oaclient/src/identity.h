/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
/*
 * private header -- not exported.
 */

#ifndef INCLUDED_OACLIENT_SOMEBODY_H
#define INCLUDED_OACLIENT_SOMEBODY_H

struct oaclient_identity {
    struct oaclient_ctx *ctx;
    char *user;
    char *realm;
    char *scope;
    char *flow;                 /* OAUTH, YDN-Direct-OAuth, ... */
    char *authorization_url;
    char *refresh_url;
    char *initiate_url;
    int rowid;
};

int oaclient_identity_set_flow(struct oaclient_identity *, const char *);
const char * oaclient_identity_get_flow(struct oaclient_identity *);


int oaclient_identity_set_rowid(struct oaclient_identity *self, unsigned int row);
int oaclient_identity_get_rowid(struct oaclient_identity *self);

#endif /* INCLUDED_OACLIENT_SOMEBODY_H */
