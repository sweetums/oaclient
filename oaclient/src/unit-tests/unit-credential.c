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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "oaclient.h"
#include "credential.h"
#include "unit_test_utils.h"

#include "ctx.h"
#include "sql_commands.h"
#include <sqlite3.h>

#define NUMBERS "123456789012345678901234567890" 


/**
 * tunnel_request_mac
 *
 * Generates the HTTP payload to access a resource with a signed
 * MAC style authentication.
 */

int main(int argc, char **argv)
{
    int errcount = 0, result;
    char *sqlerr;

    struct oaclient_credential *this;
    struct oaclient_ctx *ctx;

    result = oaclient_credential_create(&this, NULL);

    errcount += print_result("oaclient_credential_create", "positive test", 1, 
		 OAC_OK == result);

    result = oaclient_ctx_create(&ctx, NULL);

    if (OAC_OK != result) {
      printf("oaclient_ctx_create failed: %d\n", result);
      exit(1);
    }

    sqlite3_exec(ctx->db, SQL_DB_UNIT_TESTS_DATA, NULL, NULL, &sqlerr);


#define TEST_EXPANSION(field, value)    result = oaclient_credential_set_ ## field(this, value); \
    errcount += print_result("oaclient_credential_set/get_" #field, "positive test", 1, \
			     !strcmp(value, oaclient_credential_get_ ## field(this))); \

    TEST_EXPANSION(token, NUMBERS+0);
    TEST_EXPANSION(secret, NUMBERS+1);

    result = oaclient_credential_set_expiry(this, 42);
    errcount += print_result("oaclient_credential_set/get_expiry", "positive test", 1,
			     2 > (42 + time(NULL)) - oaclient_credential_get_expiry(this));


#define LINK_URL_OAI    "https://login.yahoo.com/v1/initiate"
#define LINK_URL_OAA    "https://login.yahoo.com/v1/auth"
#define LINK_URL_OAT    "https://login.yahoo.com/v1/auth"
#define LINK_URL_OA2I   "https://login.yahoo.com/oauth"
#define LINK_URL_OA2T   "https://login.yahoo.com/oauth"

    char* discovery = "HTTP/1.1 401 Unauthorized\r\n"
                      "WWW-Authenticate: BEARER realm=\"example.com\"\r\n"
                      "Link: <" LINK_URL_OAI  "> rel=\"oauth-initiate\"\r\n"
                      "Link: <" LINK_URL_OAA  "> rel=\"oauth-authorize\"\r\n"
                      "Link: <" LINK_URL_OAT  "> rel=\"oauth-token\"\r\n"
                      "Link: <" LINK_URL_OA2I "> rel=\"oauth2-authenticator\"\r\n"
                      "Link: <" LINK_URL_OA2T "> rel=\"oauth2-token\"\r\n"
                      "\r\n";


    char* bad_discovery = "HTTP/1.1 401 Unauthorized\r\n"
                          "WWW-Authenticate: BEARER realm=\"example.com\"\r\n"
                          "Link: <" LINK_URL_OAI  "> rel=\"oauth-initiate\"\r\n"
                          "Link: <" LINK_URL_OAA  "> rel=\"oauth-authorize\"\r\n"
                          "Link: <" LINK_URL_OA2I "> rel=\"oauth2-authenticator\"\r\n"
                          "\r\n";

    result = oaclient_credential_update_from_discovery(this, ctx, discovery);
    errcount += print_result("oaclient_credential_update_from_discovery", "positive test", 1,
                             OAC_OK == result); 
    
    result = oaclient_credential_update_from_discovery(this, ctx, bad_discovery);
    errcount += print_result("oaclient_credential_update_from_discovery", "negative test", 1,
                             OAC_BADPROT == result); 
    
    struct oaclient_credential *foo = NULL;
    struct oaclient_endpoint *ep = NULL;

    result = oaclient_endpoint_create(&ep);
    result = oaclient_endpoint_set_port(ep, 143);
    result = oaclient_endpoint_set_hostname(ep, "imap.example.com");
    result = oaclient_endpoint_set_username(ep, "user@example.com");
 
    result =  oaclient_get_credential_for_endpoint(&foo, ctx, ep);
    errcount += print_result("oaclient_get_credential_for_endpoint", "positive test", 1,
                             OAC_OK == result); 

    oaclient_credential_destroy(foo);

    struct oaclient_identity *who;
    oaclient_identity_create(&who);
    oaclient_identity_set_user(who, "user@example.com");
    oaclient_identity_set_realm(who, "example.com");
    oaclient_identity_set_scope(who, "demo");

    result =  oaclient_get_credential_from_cache(&foo, ctx, who);
    errcount += print_result("oaclient_get_credential_from_cache", "positive test", 1,
                             OAC_OK == result); 

    oaclient_credential_destroy(foo);



    oaclient_endpoint_destroy(ep);
    oaclient_ctx_destroy(ctx);
    oaclient_credential_destroy(this);
    
    /* */    
    printf("\nError count = %i\n\n", errcount);

    return (errcount > 0);;
}


