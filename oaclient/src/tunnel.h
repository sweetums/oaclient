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
#ifndef INCLUDED_TUNNEL_H
#define INCLUDED_TUNNEL_H

#include "oaclient.h"

#include "ctx.h"
#include "credential.h"
#include "identity.h"

#include <jansson.h>


/* 
 * Required for Curl parsing.
 */
typedef struct curl_data {
  char *data;
  int code;
  int size;
  int offset;
} curl_data_t;

size_t tunnel_curl_write_cb( void *buffer, size_t size, size_t nmemb, void *userp);
size_t tunnel_curl_hdr_cb(void *buffer, size_t size, size_t nmemb, void *userp);

 
/**
 * tunnel_authenticate
 *
 * Wrapper for the authenticate routines.  Determines
 * which one needs to go and uses that.
 */
int tunnel_authenticate(struct oaclient_ctx *ctx,
			struct oaclient_credential *cred,
			struct oaclient_endpoint *ep,
			int flow,
			const char *password);

/**
 * tunnel_refresh
 *
 * Wrapper for the refresh logic.  Picks the right flow and
 * uses that.  Takes a rock to throw to the YDN flow if needed.
 */
int tunnel_refresh(struct oaclient_ctx *ctx,
		   struct oaclient_credential *cred,
		   int flow,
		   const char *rock);

/**
 * tunnel_oauth2_authenticate
 *
 * Do an Oauth 2 password credential authentication.
 */
int tunnel_oauth2_authenticate(struct oaclient_ctx *ctx,
			       struct oaclient_credential *cred,
			       struct oaclient_endpoint *ep,
			       const char *password);

/**
 * tunnel_oauth2_refresh
 *
 * Do an Oauth 2 password credential authentication.
 */
int tunnel_oauth2_refresh(struct oaclient_ctx *ctx,
			  struct oaclient_credential *cred);

/**
 * tunnel_ydn_refresh_token
 *
 * Yahoo! YDN specific "Direct Oauth" token refresh support..
 */
int tunnel_ydn_refresh(struct oaclient_ctx *ctx,
                       struct oaclient_credential *cred,
                       const char *ydnPART);

/**
 * tunnel_ydn_authenticate
 *
 * Yahoo! YDN specific "Direct Oauth" authentication flow support.
 *
 */
int tunnel_ydn_authenticate(struct oaclient_ctx *ctx,
                            struct oaclient_credential *cred,
                            struct oaclient_endpoint *ep,
                            const char *password);

/*
** OK, the "tunnel_" naming scheme is odd.  It initially meant
** tunneling the auth through somethign else, initially SASL,
** but the semantics are changing, because the SASL message format 
** is changing from HTTP to control-A separated.
*/
/**
 * tunnel_parse_discovery
 *
 * Parse an HTTP blob which should contain discovery information.
 */
int tunnel_parse_discovery();


/**
 * tunnel_request_discovery
 *
 * Generates the HTTP payload to request discovery information.
 */
int tunnel_request_discovery(struct oaclient_ctx *ctx,
                             struct oaclient_endpoint *where,
                             char **payload);

/**
 * tunnel_auth_credentialed
 *
 * Figures out what kind of request to generate and does that.
 */
int tunnel_auth_credentialed(struct oaclient_ctx *ctx,
			     struct oaclient_credential *cred,
                             struct oaclient_endpoint *ep,
			     char **out);
/**
 * tunnel_auth_oauth
 *
 * Generates the HTTP payload to access a resource with a signed
 * OAuth 1.0a style access request for a protected resource.
 */
int tunnel_auth_oauth(struct oaclient_ctx *ctx,
		      struct oaclient_credential *cred,
		      struct oaclient_endpoint *ep,
		      char **out);
/**
 * tunnel_auth_bearer
 *
 * Generates the HTTP payload to access a resource with a 
 * bearer token.
 */
int tunnel_auth_bearer(struct oaclient_ctx *ctx,
		       struct oaclient_credential *cred,
		       struct oaclient_endpoint *ep,
		       char **out);
/**
 * tunnel_auth_mac
 *
 * Generates the HTTP payload to access a resource with a signed
 * MAC style authentication.
 */
int tunnel_auth_mac(struct oaclient_ctx *ctx,
		    struct oaclient_credential *cred,
		    struct oaclient_endpoint *ep,
		    char **out);


/* parser tools */
char *find_post_variable(char *haystack, char *name);

/*
char *findstr_a_before_b(char *haystack, char *a, char *b);
char *findchr_a_before_b(char *haystack, char a, char b);
char *skip_quoted_string(char *haystack, char *open, char *close, char *escaped_close);
char *find_unquoted_string(char *haystack, char *needle, char *open,
                           char *close, char *escaped_close);
*/

const char *find_strncase_inlist(const char*list[], char *needle, int len);
int find_strncase_index_inlist(const char*list[], const char *needle, int len);

/*
int tunnel_store_link(struct oaclient_ctx *ctx,
                      struct oaclient_credential *cred,
                      const char *payload,
                      int type);

int tunnel_store_linkn(struct oaclient_ctx *ctx,
                       struct oaclient_credential *cred,
                       const char *payload,
                       int type,
                       int size);

int tunnel_parse_link(struct oaclient_ctx *ctx,
                      struct oaclient_credential *cred,
                      const char *payload,
                      const char *scheme,
                      const char *rel,
                      int type);

int tunnel_parse_links(struct oaclient_ctx *ctx,
                       struct oaclient_credential *cred,
                       const char *payload,
                       const char *scheme,
                       const char *rel,
                       int type);
*/

int tunnel_parse_oauth_links(struct oaclient_ctx *ctx,
			     struct oaclient_credential *cred,
			     const char *payload,
			     const char *scheme);

int tunnel_parse_oauth2_links(struct oaclient_ctx *ctx,
			      struct oaclient_credential *cred,
			      const char *payload,
			      const char *scheme);

/* new discovery stuff */
// int t_get_hostmeta(struct oaclient_endpoint *ep, json_t **jobj);

// int t_curl_getjson(const char *target, json_t **jobj);

/*
** Internal utility stuff.
*/
int is_valid_hostname(const char *in);

int t_get_hostmeta(const char *host, json_t **jobj);
int t_curl_getjson(const char *target, json_t **jobj);

int t_extract_oauth2_rel(struct oaclient_ctx *ctx,
                         struct oaclient_identity *who,
                         json_t *jobj);
#endif
