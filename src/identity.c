/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "oaclient.h"

#include "identity.h"
#include "accessor.h"


#define CC_ACCESSORS(field)                                     \
    DEFINE_GETTER(const char *, oaclient_identity, field);      \
    DEFINE_SETTER(const char *, oaclient_identity, field, (strdup(v)));

#define CC_INT_ACCESSORS(field)                                     \
    DEFINE_GETTER(int, oaclient_identity, field);      \
    DEFINE_INT_SETTER(unsigned int, oaclient_identity, field, v);

CC_ACCESSORS(user);
CC_ACCESSORS(realm);
CC_ACCESSORS(scope);
// CC_ACCESSORS(scheme);
CC_ACCESSORS(flow);
CC_ACCESSORS(initiate_url);
CC_ACCESSORS(authorization_url);
CC_ACCESSORS(refresh_url);

CC_INT_ACCESSORS(rowid);


#undef CC_ACCESSORS
#undef CC_INT_ACCESSORS

int oaclient_identity_create(struct oaclient_identity **out)
{
    *out = calloc(sizeof(**out), 1);
    if (!*out) {
        return ENOMEM;
    }
    return 0;
}

#define IDENTITY_STRDUP(dest, src, name)	\
  if (src -> name) {                            \
    dest -> name = strdup(src->name);           \
    if (! dest -> name) {		        \
       oaclient_identity_destroy(dest);         \
       return ENOMEM;                           \
    }                                           \
  }                     

int oaclient_identity_clone(struct oaclient_identity **out, struct oaclient_identity *in)
{
    *out = calloc(sizeof(**out), 1);

    if (!*out) {
        return ENOMEM;
    }

    IDENTITY_STRDUP((*out), in, user)
    IDENTITY_STRDUP((*out), in, realm)
    IDENTITY_STRDUP((*out), in, scope)
      // IDENTITY_STRDUP((*out), in, scheme)
    IDENTITY_STRDUP((*out), in, flow)
    IDENTITY_STRDUP((*out), in, initiate_url)
    IDENTITY_STRDUP((*out), in, authorization_url)
    IDENTITY_STRDUP((*out), in, refresh_url)
    
    return 0;
}

void oaclient_identity_destroy(struct oaclient_identity *self)
{
    free(self->user);
    free(self->realm);
    free(self->scope);
    //    free(self->scheme);
    free(self->flow);
    free(self->initiate_url);
    free(self->authorization_url);
    free(self->refresh_url);
    free(self);
}


