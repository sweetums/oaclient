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
#include "endpoint.h"
#include "ctx.h"
#include "unit_test_utils.h"
#include <sqlite3.h>
#include "sql_commands.h"



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

    struct oaclient_endpoint *ep;

    struct oaclient_ctx *ctx;

    if (OAC_OK != (result = oaclient_ctx_create(&ctx, NULL))) {
        printf("Failed to create context!\n");
	exit(1);
    }

    sqlite3_exec(ctx->db, SQL_DB_UNIT_TESTS_DATA, NULL, NULL, &sqlerr);

    result = oaclient_endpoint_create(&ep);

    errcount += print_result("oaclient_endpoint_create", "positive test", 1, 
		 OAC_OK == result);

    result = oaclient_endpoint_set_port(ep, 143);
    errcount += print_result("oaclient_endpoint_set/get_port", "positive test", 1, 
			     143 == oaclient_endpoint_get_port(ep));

    result = oaclient_endpoint_set_hostname(ep, "imap.example.com");
    errcount += print_result("oaclient_endpoint_set/get_hostname", "positive test", 1, 
			     !strcmp("imap.example.com", oaclient_endpoint_get_hostname(ep)));

    result = oaclient_endpoint_set_username(ep, "user@example.com");
    errcount += print_result("oaclient_endpoint_set/get_username", "positive test", 1, 
			     !strcmp("user@example.com", oaclient_endpoint_get_username(ep)));

    result = oaclient_endpoint_set_path(ep, "/");
    errcount += print_result("oaclient_endpoint_set/get_path", "positive test", 1, 
			     !strcmp("/", oaclient_endpoint_get_path(ep)));


    result = oaclient_endpoint_set_username(ep, "");
    result = oaclient_endpoint_isCached(ctx, ep);
    errcount += print_result("oaclient_endpoint_isCached", "negative test", 1, 
			     OAC_FAIL == result);

    result = oaclient_endpoint_set_username(ep, "user@example.com");
    result = oaclient_endpoint_isCached(ctx, ep);
    errcount += print_result("oaclient_endpoint_isCached", "positive test", 1, 
			     OAC_OK == result);


    oaclient_endpoint_destroy(ep);

    /* */    
    printf("\nError count = %i\n\n", errcount);

    oaclient_ctx_destroy(ctx);

    return (errcount > 0);;
}


