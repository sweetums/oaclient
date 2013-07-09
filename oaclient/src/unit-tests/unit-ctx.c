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
#include "ctx.h"
#include "unit_test_utils.h"



/**
 * tunnel_request_mac
 *
 * Generates the HTTP payload to access a resource with a signed
 * MAC style authentication.
 */

char *ROCK = "No throwing please....";

int main(int argc, char **argv)
{
    int errcount = 0, result;
    void *resultp;

    struct oaclient_ctx *cp;

    result = oaclient_ctx_create(&cp, NULL);

    errcount += print_result("oaclient_ctx_create", "positive test", 1, 
		 OAC_OK == result);

    resultp = oaclient_ctx_set_rock(cp, ROCK);
    errcount += print_result("oaclient_ctx_set/get_rock", "positive test", 1, 
			     ROCK == oaclient_ctx_get_rock(cp));

    oaclient_ctx_destroy(cp);

    /* */    
    printf("\nError count = %i\n\n", errcount);

    return (errcount > 0);;
}


