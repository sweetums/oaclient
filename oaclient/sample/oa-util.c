/* Oauth client library utility program
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

#include <stdio.h>
#include <termios.h>
#include <ctype.h>
#include <signal.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "oaclient.h"
#include "endpoint.h"
#include "tunnel.h"

#include <jansson.h>


/*
 * Terminal configuration
 */
struct termios term_saved;



/*
 * Restore terminal configuration
 */
void fix_terminal(void) {
  if(-1 == tcsetattr(fileno(stdin), TCSANOW, &term_saved)){
    perror("tcsetattr(): Cannot restore terminal.  Run 'stty sane'.");
    exit(EXIT_FAILURE);
  }
}

/*
 * Handler for SIGINT
 */
void sigint_handler(int sig) {
  if (SIGINT == sig) {
    fix_terminal();
  }
  exit(EXIT_SUCCESS);
}


/**
 * tunnel_request_mac
 *
 * Generates the HTTP payload to access a resource with a signed
 * MAC style authentication.
 */
#define MAXPASSWD 128
int askpass(struct oaclient_callback_args *args, char **out) {
    struct termios term;
    struct sigaction sigaction_sigint;
    char passwd[MAXPASSWD], *tmp;

    if (!out)
	return OAC_FAIL;
    
    passwd[0] = (char)0;

    /* Save current terminal configuration */
    if (-1 == tcgetattr(fileno(stdin), &term_saved)) {
        perror("tcgetattr(): Can't save current terminal setting.");
        exit(1);
    }
    term = term_saved;

    /* Set signal for SIGINT */
    memset(&sigaction_sigint, 0, sizeof(struct sigaction));
    sigaction_sigint.sa_handler = sigint_handler;
    sigaction_sigint.sa_flags = 0;
    if ( sigaction(SIGINT, &sigaction_sigint, NULL) < 0 ) {
        perror("sigaction()");
        exit(1);
    }

    /* adjust tset */
    term.c_lflag &= ~ECHO;  /* stty -echo  */
    if ( -1 == tcsetattr(fileno(stdin), TCSANOW, &term) ) {
        perror("tcsetattr(): Cannot update terminal setting");
        exit(EXIT_FAILURE);
    }

    /* Prompt, then get a line from stdin */
    printf("Password: ");
    fgets(passwd, MAXPASSWD, stdin);
    printf("\n");

    tmp = rindex(passwd, '\n');
    if (NULL != tmp) *tmp = '\0';

    tmp = rindex(passwd, '\r');
    if (NULL != tmp) *tmp = '\0';

    /* Restore terminal configuration */
    fix_terminal();

    *out = strdup(passwd);
    if (NULL == *out)
	return OAC_NOMEM;

    return OAC_OK;
}

/*
 * usage()
 *
 * Because everyone needs a little help now and then.
 */
void usage() {
    printf("\n"
	   "\toa-util <command> <arguments>*\n"
	   "\n"
	   "\tlist\n"
	   "\t\tList known identities.\n"
	   "\tclear\n"
	   "\t\tClear the entire cache including all credentials, identities, and endpoints.\n"
	   "\tforget <username>\n"
	   "\t\tClear the identity information and credential for the username.\n"
	   "\t\n"
	   "\t\n"
	   "\n");
}

/* */
void die(const char *err) {
    printf("Error: %s\n", err);
    exit(1);
}

/* */
void sub_list(int argc, char **argv) {
}

/* */
void sub_clear(int argc, char **argv) {
    int result;
    struct oaclient_ctx *ctx;
    struct oaclient_callbacks cb = {0, &askpass};

    result = oaclient_ctx_create(&ctx, &cb);
    if (OAC_OK != result)
	die("Unable to initialize client context/DB.");

    result = oaclient_cache_clear(ctx);
    if (OAC_OK != result)
	die("Unable to open/clear the cache.");

    return;
}

/* */
void sub_forget(int argc, char **argv) {
}

/* Note: in this case 0 is true and 1 is everything else */

int main(int argc, char **argv) {

    if (2 < argc || !argv[1] || !*argv[1]) {
	usage();
	exit(1);
    }

    if (0 == strcmp(argv[1], "list")) {
	sub_list(argc, argv);
	exit(0);
    }

    if (0 == strcmp(argv[1], "clear")) {
	sub_clear(argc, argv);
	exit(0);
    }

    if (0 == strcmp(argv[1], "forget")) {
	sub_forget(argc, argv);
	exit(0);
    }

    return(0);
}




#if 0
    int errcount = 0, result;
    char *tmp;

    result = askpass(&cb_args, &tmp);


struct oaclient_callbacks cb = {0, &askpass};
struct oaclient_ctx *ctx;
struct oaclient_credential *cred;
struct oaclient_identity *ident;
struct oaclient_endpoint *ep;

/* populate the things we might need */
result = oaclient_ctx_create(&ctx, &cb);
result = oaclient_endpoint_create(&ep);
result = oaclient_identity_create(&ident);
result = oaclient_credential_create(&cred, ident);




    /* testing more complex things... */

    struct oaclient_ctx *ctx;
    struct oaclient_credential *cred;
    struct oaclient_identity *ident;
    struct oaclient_endpoint *ep;
    result = oaclient_endpoint_create(&ep);


    struct oaclient_callback_args cb_args = {0, NULL, ctx, ident};
    struct oaclient_callbacks cb = {0, &askpass};

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
    result = askpass(&cb_args, &password);
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

#endif
