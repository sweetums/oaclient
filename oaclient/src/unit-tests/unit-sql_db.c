/* Oauth SASL plugin
 * Bill Mills, Tim Showalter
 * $Id:  $
 *
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>

#include "ctx.h"
#include "credential.h"
#include "endpoint.h"
#include "identity.h"
#include "oaclient.h"
#include "sql_db.h"
#include "unit_test_utils.h"


void setup_cred(struct oaclient_credential *cred)
{
  oaclient_credential_set_token(cred, "i'm a token");
  oaclient_credential_set_scheme(cred, "i'm a scheme");
  oaclient_credential_set_secret(cred, "i'm a secret");
  oaclient_credential_set_session(cred, "i'm a session");
  oaclient_credential_set_expiry(cred, 123456);
}

void setup_id(struct oaclient_identity *id)
{
  oaclient_identity_set_user(id, "i'm a user");
  oaclient_identity_set_realm(id, "i'm a realm");
  oaclient_identity_set_scope(id, "i'm a scope");
  oaclient_identity_set_initiate_url(id, "i'm a initiate_url");
  oaclient_identity_set_authorization_url(id, "i'm a authorization_url");
  oaclient_identity_set_refresh_url(id, "i'm a refresh_url");
}

void setup_ep(struct oaclient_endpoint *ep)
{
  oaclient_endpoint_set_username(ep, "i'm a user");
  oaclient_endpoint_set_hostname(ep, "i'm a hostname");
  oaclient_endpoint_set_path(ep, "i'm a path");
  oaclient_endpoint_set_port(ep, 1234);
}

/**
 *
 */

int main(int argc, char **argv)
{
    int errcount = 0, result;
    //    sqlite3 *db;

    struct oaclient_ctx *ctx;
    struct oaclient_credential *cred;
    struct oaclient_endpoint *ep;
    struct oaclient_identity *id;

    result = oaclient_ctx_create(&ctx, NULL);

    /* The basics */
    result = oac_db_open(ctx, NULL);

    errcount += print_result("oac_db_open", "positive test", 1, 
		 OAC_OK == result);

    oac_db_close(ctx);

    /* OK set up for the cache operations. */

    result = oaclient_credential_create(&cred, NULL);
    result = oaclient_identity_create(&id);
    result = oaclient_credential_set_identity(cred, id);
    result = oaclient_endpoint_create(&ep);
    setup_cred(cred);
    setup_ep(ep);
    setup_id(id);

    result = oaclient_cache_update(ctx, ep, id, cred);
    errcount += print_result("oaclient_cache_update", "positive test", 1, 
		 OAC_OK == result);

    oaclient_identity_set_user(id, "i'm a user too");
    oaclient_endpoint_set_username(ep, "i'm a user too");

    result = oaclient_cache_update(ctx, ep, id, cred);
    errcount += print_result("oaclient_cache_update", "second user", 1, 
		 OAC_OK == result);


    oaclient_credential_destroy(cred);    
    oaclient_endpoint_destroy(ep);    
    oaclient_identity_destroy(id);    
    oaclient_ctx_destroy(ctx);    


    /* */    
    printf("\nError count = %i\n\n", errcount);

    return (errcount > 0);;
}


