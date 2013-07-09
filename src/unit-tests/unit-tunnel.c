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

#include <curl/curl.h>
#include <curl/easy.h>

#include "oaclient.h"
#include "endpoint.h"
#include "tunnel.h"

#include "unit_test_utils.h"

#include <jansson.h>


/**
 * tunnel_request_mac
 *
 * Generates the HTTP payload to access a resource with a signed
 * MAC style authentication.
 */
int askpass_stub(struct oaclient_callback_args *args, char **out) {
    *out = strdup("_92105");
    
    return OAC_OK;
}


/* Note: in this case 0 is true and 1 is everything else */

int main(int argc, char **argv)
{
    int errcount = 0, result;


    /* check the hostname validation routine */

    errcount += print_result("is_valid_hostname", "positive test", 0, 
			     is_valid_hostname("localhost"));

    errcount += print_result("is_valid_hostname", "positive test", 0, 
			     is_valid_hostname("a.b.com"));

    errcount += print_result("is_valid_hostname", "negative test", 1, 
			     is_valid_hostname("c..b.com"));

    errcount += print_result("is_valid_hostname", "negative test", 1, 
			     is_valid_hostname("host+name"));

    errcount += print_result("is_valid_hostname", "negative test", 1, 
			     is_valid_hostname("host name"));

    errcount += print_result("is_valid_hostname", "empty test", 1, 
			     is_valid_hostname(""));

    errcount += print_result("is_valid_hostname", "null test", 1, 
			     is_valid_hostname(NULL));


    /* test the list searcher function */
    const char *thislist[] = {"a", "b", "c", NULL};

    errcount += print_result("find_strncase_inlist", "positive first", 1,
			     (int)find_strncase_inlist(thislist, "a", 1));

    errcount += print_result("find_strncase_inlist", "positive middle", 1,
			     (int)find_strncase_inlist(thislist, "a", 1));

    errcount += print_result("find_strncase_inlist", "positive last", 1,
			     (int)find_strncase_inlist(thislist, "a", 1));

    errcount += print_result("find_strncase_inlist", "positive case", 1,
			     (int)find_strncase_inlist(thislist, "A", 1));

    errcount += print_result("find_strncase_inlist", "negative", 0,
			     (int)find_strncase_inlist(thislist, "Z", 1));


    /* find_post_variable */
    char *pv, *pv_payload = "a=foo&b=bar&c=baz";
    
    pv = find_post_variable(pv_payload, "a");
    errcount += print_result("find_post_variable: first", "positive", 1,
                             pv && !strcmp("foo", pv));
    free(pv);

    pv = find_post_variable(pv_payload, "b");
    errcount += print_result("find_post_variable: middle", "positive", 1,
                             pv && !strcmp("bar", pv));
    free(pv);

    pv = find_post_variable(pv_payload, "c");
    errcount += print_result("find_post_variable: last", "positive", 1,
                             pv && !strcmp("baz", pv));
    free(pv);

    pv = find_post_variable(pv_payload, "d");
    errcount += print_result("find_post_variable: key not present", "negative", 1,
                             !pv);
    free(pv);

    pv = find_post_variable("dabcdefg", "d");
    errcount += print_result("find_post_variable: bad fmt", "negative", 1,
                             !pv);
    free(pv);


    /* testing more complex things... */

    struct oaclient_ctx *ctx;
    struct oaclient_credential *cred;
    struct oaclient_identity *ident;
    struct oaclient_endpoint *ep;
    result = oaclient_endpoint_create(&ep);


    struct oaclient_callback_args cb_args = {0, NULL, ctx, ident};
    struct oaclient_callbacks cb = {0, &askpass_stub};

    result = oaclient_ctx_create(&ctx, &cb);
    result = oaclient_credential_create(&cred, NULL);
    result = oaclient_identity_create(&ident);
    result = oaclient_credential_set_identity(cred, ident);


    /* test the discovery functions */

    // int t_get_hostmeta(struct oaclient_endpoint *ep, json_t **jobj);
    json_t *jobj;

    result = oaclient_endpoint_set_hostname(ep, "localhost");

    // Note we assume that localhost has a well-known
    result = t_curl_getjson("http://localhost/.well-known/host-meta.json", &jobj); 
    errcount += print_result("t_curl_getjson from localhost", "positive", 0, result);
    json_object_clear(jobj);

    result = t_get_hostmeta("localhost", &jobj); 
    errcount += print_result("t_curl_getjson from localhost", "positive", 0, result);



    /* Now testing discovery parsers */

    /* XXXXXXXXX  The OAuth 2 linkes below are **WRONG*** or at least unworking at this time.*/

#define LINK_URL_OAI    "https://login.yahoo.com/WSLogin/V1/get_auth_token"
#define LINK_URL_OAA 	"https://api.login.yahoo.com/oauth/v2/get_token"
#define LINK_URL_OAT 	"https://api.login.yahoo.com/oauth/v2/get_token"
#define LINK_URL_OA2I	"https://login.yahoo.com/oauth"
#define LINK_URL_OA2T	"https://login.yahoo.com/oauth"

    char* discovery_oauth = "HTTP/1.1 401 Unauthorized\r\n"
	              "WWW-Authenticate: oauth realm=\"example.com\"\r\n"
	              "Link: <" LINK_URL_OAI  "> rel=\"oauth-initiate\"\r\n"
	              "Link: <" LINK_URL_OAA  "> rel=\"oauth-authorize\"\r\n"
	              "Link: <" LINK_URL_OAT  "> rel=\"oauth-token\"\r\n"
                      "\r\n";


    char * wf_discovery_json_y = "{\"expires\" : \"2014-03-13T20:56:11Z\",\"links\" : "
      "[{\"rel\" : \"oauth2-authorize\", \"href\" : \"https://api.login.yahoo.com/oauth2/request_auth\"},"
      "{\"rel\" : \"oauth2-token\", \"href\" : \"https://api.login.yahoo.com/oauth2/get_token\","
      "\"grant-types\" : \"code password\", \"token-types\" : \"bearer\" }]}";


    char * wf_discovery_json = "{\"expires\" : \"2014-03-13T20:56:11Z\",\"links\" : "
      "[{\"rel\" : \"oauth2-authorize\", \"href\" : \"http://localhost/oauth2.php\"},"
      "{\"rel\" : \"oauth2-token\", \"href\" : \"https://localhost/oauth2-token.php\","
      "\"grant-types\" : \"password\", \"token-types\" : \"bearer\" }]}";

    char * sasl_disc_json = "{\"error\" : 401, \"schemes\" : \"bearer\"}";
    char * sasl_disc_json_bad = "{\"error\" : 401 ,\"schemes\" : \"foobar\"}";


    json_error_t jerror;
    json_object_clear(jobj);

    result = t_extract_oauth2_rel(ctx, cred->ident, jobj);
    errcount += print_result("t_extract_oauth2_rel: empty json", "positive", 1,
                             OAC_FAIL == result);

    jobj = json_loads(wf_discovery_json, &jerror);

    result = t_extract_oauth2_rel(ctx, cred->ident, jobj);
    errcount += print_result("t_extract_oauth2_rel: simple test", "positive", 1,
                             OAC_OK == result);

    json_object_clear(jobj);

    
    /* Testing YDN direct oauth stuff. */
    result = oaclient_endpoint_set_username(ep, "muppetsweetums");
    result = tunnel_parse_discovery(ctx, cred, discovery_oauth);
    errcount += print_result("tunnel_parse_discovery: no JSON", "negaive", 1,
                             OAC_FAIL == result);
    result = tunnel_parse_discovery(ctx, cred, sasl_disc_json);
    errcount += print_result("tunnel_parse_discovery", "positive", 1,
                             OAC_OK == result);

    result = tunnel_parse_discovery(ctx, cred, sasl_disc_json_bad);
    errcount += print_result("tunnel_parse_discovery", "negative: no valid scheme", 1,
                             OAC_OK != result);

    /* Now we have a parsed discovery to populate the cred, 
    ** test the ydn auth stuff 
    */
    char *password;
    result = askpass_stub(&cb_args, &password);
    //    result = tunnel_ydn_authenticate(ctx, cred, ep, password);
    //    errcount += print_result("tunnel_ydn_authenticate: good discovery", "positive", 1,
    //                         OAC_OK == result);

    /* now just refrsh the token from above */
    //    result = tunnel_ydn_refresh(ctx, cred, NULL);
    //    errcount += print_result("tunnel_ydn_refresh: have tokens", "positive", 1,
    //                         OAC_OK == result);

    free(password);

    /* now we can test tunnel_auth_oauth since we have a credential */
    const char *testusername = "user@localhost";
    const char *testhostname = "localhost";
    //    const char *testpathname = "/path";
    char *testdisc;
    int testport = 143;

    char *signed_request;

    result = oaclient_endpoint_set_hostname(ep, testhostname);

    result = tunnel_auth_oauth(ctx, cred, ep, &signed_request);
    errcount += print_result("tunnel_auth_oauth: sign a request", "positive", 1,
                             OAC_OK == result);
    free(signed_request);
    signed_request = NULL;

    /* Test the protocol specific message generation. */

    result = oaclient_endpoint_set_hostname(ep, "localhost");
    result = oaclient_endpoint_set_port(ep, 143);
    result = oaclient_credential_set_token(cred, "mock_up_bearer_token");

    result = tunnel_auth_bearer(ctx, cred, ep, &signed_request);
    errcount += print_result("tunnel_auth_bearer", "smoke test", 1,
                             OAC_OK == result);

    if (signed_request) oaclient_free(signed_request);
    signed_request = NULL;

    /* and now test the switcher */

    result = tunnel_auth_credentialed(ctx, cred, ep, &signed_request);
    errcount += print_result("tunnel_auth_credentialed: sign a request", "positive", 1,
                             OAC_OK == result);
    free(signed_request);
    signed_request = NULL;

    /* 
     * Now we'll test the OAuth 2 stuff.  Parse in some discovery and 
     * test authentication.
     */
    jobj = json_loads(wf_discovery_json_y, &jerror);
    result = t_extract_oauth2_rel(ctx, cred->ident, jobj);
    json_object_clear(jobj);

    result = oaclient_endpoint_set_username(ep, "muppetsweetums");
    result = tunnel_oauth2_authenticate(ctx, cred, ep, "_92105");
    errcount += print_result("tunnel_oauth2_authenticate: test cred fetch", "positive", 1,
                             OAC_OK == result);

    result = tunnel_oauth2_refresh(ctx, cred);
    errcount += print_result("tunnel_oauth2_refresh: test cred refresh", "positive", 1,
                             OAC_OK == result);


    // Now try a full parse, handing in discovery.
    result = oaclient_tunnel_endpoint(ctx, &signed_request, &cred,
				      ep, sasl_disc_json);
    errcount += print_result("oaclient_tunnel_endpoint: parse discovery with current state", "positive", 1,
                             OAC_OK == result);
    free(signed_request);


    // oaclient_credential_destroy(cred);

    /* Testing tunnel_request_discovery  */

    result = oaclient_endpoint_set_port(ep, testport);
    result = oaclient_endpoint_set_hostname(ep, "imap.example.com");
    result = oaclient_endpoint_set_username(ep, "foobar");

    result = oaclient_endpoint_set_port(ep, 0);
    result = tunnel_request_discovery(ctx, ep, &testdisc);
    errcount += print_result("tunnel_request_discovery: no port set", "negative", 1,
                             OAC_OK != result);
    result = oaclient_endpoint_set_port(ep, testport);
    free(testdisc);

    result = oaclient_endpoint_set_hostname(ep, "");
    result = tunnel_request_discovery(ctx, ep, &testdisc);
    errcount += print_result("tunnel_request_discovery: no hostname", "negative", 1,
                             OAC_OK != result);
    result = oaclient_endpoint_set_hostname(ep, "imap.example.com");
    free(testdisc);

    result = oaclient_endpoint_set_username(ep, testusername);
    result = tunnel_request_discovery(ctx, ep, &testdisc);
    errcount += print_result("tunnel_request_discovery", "positive", 1,
                             OAC_OK == result);
    free(testdisc);


    /* */

    oaclient_endpoint_destroy(ep);

    oaclient_credential_destroy(cred);

    oaclient_identity_destroy(ident);

    oaclient_ctx_destroy(ctx);

    /* */    
    printf("\nError count = %i\n\n", errcount);

    return (errcount > 0);;
}


