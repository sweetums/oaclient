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

#include "oaclient.h"
#include "identity.h"
#include "unit_test_utils.h"

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

    struct oaclient_identity *this;
    struct oaclient_ctx *ctx;

    result = oaclient_identity_create(&this);

    result = oaclient_ctx_create(&ctx, NULL);

    errcount += print_result("oaclient_identity_create", "positive test", 1, 
		 OAC_OK == result);

#define TEST_EXPANSION(field, value)    result = oaclient_identity_set_ ## field(this, value); \
    errcount += print_result("oaclient_identity_set/get_" #field, "positive test", 1, \
			     !strcmp(value, oaclient_identity_get_ ## field(this))); \

    TEST_EXPANSION(user, NUMBERS+0);
    TEST_EXPANSION(user, NUMBERS+1);
    TEST_EXPANSION(realm, NUMBERS+2);
    TEST_EXPANSION(scope, NUMBERS+3);
    TEST_EXPANSION(initiate_url, NUMBERS+5);
    TEST_EXPANSION(authorization_url, NUMBERS+6);
    TEST_EXPANSION(refresh_url, NUMBERS+6);

#define LINK_URL_OAI    "https://login.yahoo.com/v1/initiate"
#define LINK_URL_OAA    "https://login.yahoo.com/v1/auth"
#define LINK_URL_OAT    "https://login.yahoo.com/v1/auth"
#define LINK_URL_OA2I   "https://login.yahoo.com/oauth"
#define LINK_URL_OA2T   "https://login.yahoo.com/oauth"

    /*

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

             oaclient_identity_update_from_discovery
    result = oaclient_identity_update_from_discovery(this, ctx, discovery);
    errcount += print_result("oaclient_identity_update_from_discovery", "positive test", 1,
                             OAC_OK == result); 
    
    result = oaclient_identity_update_from_discovery(this, ctx, bad_discovery);
    errcount += print_result("oaclient_identity_update_from_discovery", "negative test", 1,
                             OAC_BADPROT == result); 
    */
    
    oaclient_ctx_destroy(ctx);
    oaclient_identity_destroy(this);
    
    /* */    
    printf("\nError count = %i\n\n", errcount);

    return (errcount > 0);;
}


