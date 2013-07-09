/* Oauth SASL plugin
 * Bill Mills, Tim Showalter
 * $Id:  $
 *
 */
/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#define _GNU_SOURCE
#define __USE_GNU      1

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <sys/types.h>
#include <regex.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include <oaclient.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "endpoint.h"
#include "tunnel.h"
#include "sql_db.h"

#include <oauth.h>


#ifndef DEBUG 
#define DEBUG 0
#endif 

#define DEBUG_PRINTF(variable) if (DEBUG) printf(#variable " is %s\n\n", variable)
#define DEBUG_PRINT(variable) if (DEBUG) printf(variable "\n")


int t_discover(struct oaclient_ctx *ctx, 
	       struct oaclient_endpoint *ep, 
	       struct oaclient_identity *ident);



/* 
 * temporary hard coded consumer key and secret (which isn't really secret in this case)
 */
/* XXXXXX need to load this from config */  

const char *ydn_consumer_key = "dj0yJmk9aE9STTFoR29kNmM2JmQ9WVdrOVVrTjRNMU5JTkRRbWNHbzlNakF3TXpFNE5UWTJNZy0tJnM9Y29uc3VtZXJzZWNyZXQmeD1kOQ--";
const char *ydn_consumer_secret = "cc36eaba8a9063f6fa7c43858320541c3236950a";


#define STRNDUP(src, len) local_strndup(src, len)

static
char *local_strndup(const char *src, int len)
{
    char *dest = malloc(len + 1);
    if (dest) {
	strncpy(dest, src, len);
	dest[len] = '\0';
    }

    return dest;
}

// const char *SUPPORTED_FLOWS[] = {"YDN", "OAUTH", "OAUTH2", NULL};
const char *SUPPORTED_FLOWS[] = {"stub no-op", "stub no-op", "OAUTH2", NULL};
enum supported_flow{FLOW_UNKNOWN=-1, FLOW_YDN=0, FLOW_OAUTH, FLOW_OAUTH2};

// const char *SUPPORTED_SCHEMES[] = {"bearer", "mac", "oauth", NULL};
const char *SUPPORTED_SCHEMES[] = {"bearer", "stub no-op", "stub no-op", NULL};
enum supported_scheme{SCHEME_UNKNOWN=-1, SCHEME_BEARER=0, SCHEME_MAC, SCHEME_OAUTH};


/*
 * Used to clean up string returned by oaclient_* functions.
 */
void oaclient_free(void *mem)
{
    if (mem) free(mem);
}

/* oaclient_tunnel_endpoint
 *
 * Taking an enpoint and context, return the payload to send.  If there is 
 * no stored credential then the payload is a discovery request.  If there
 * is a cached credential this returns the access request for the resource.
 *
 * This will prompt for password if that's required for authorization, using 
 * the callback passed in by the caller in the ctx.
 *
 * If discovery information is passed in, this presumes that the cached 
 * credential is no longer valid.  If the cached credential has a short term 
 * access token and a durable token,  the durable token is retried before the 
 * user is prompted for authorization. 
 *
 * The oaclient_credential must be cleaned up with oaclient_credential_destroy().
 * payload returned can be freed with oaclient_free().
 */
int oaclient_tunnel_endpoint(struct oaclient_ctx *ctx,
			     char ** payload, 
			     struct oaclient_credential **cred,
			     struct oaclient_endpoint *endpoint, 
			     const char *discovery)
{
    struct oaclient_credential *tmpcred;
    struct oaclient_identity *ident;
    char *out, *password;
    int result=OAC_OK, expiry;
    enum oaclient_ctx_state state = oaclient_ctx_get_state(ctx);
    enum supported_flow flow;
    const char *flowp;

    ident = oaclient_credential_get_identity(*cred);

    if (NULL == ctx) {
      return OAC_BAD_PARAM;
    }
    struct oaclient_callback_args cbargs = {0, ctx->rock, ctx, ident};


    if (discovery) {
	/* 
	 * In the new regime...  discovery communicates back a recommended scope
	 * and error code in a JSON payload.  Actual auth endpoint discovery is
	 * via WebFinger/Simple Web Discovery.
	 *
	 * If discovery is passed in:
	 * 
	 *     -   current credentials if any need a refresh.
	 *     -   we should re-do endpoint discovery
	 *
	 */
	result = tunnel_parse_discovery(ctx, *cred, discovery);
	if (OAC_OK != result)
	    return result;


	// Discover based on WebFinger and get the info.  
	// This goes into the identity inside the cred, this makes sense because
	// it's possible to have multiple authenticators for the same endpoint,
	// though from the POV of the user application this might be moot.
	result = t_discover(ctx, endpoint, ident);
	if (OAC_OK != result)
	    return result;


	/* Update the cache with the new discovery info */
	oaclient_cache_update(ctx, endpoint, ident, NULL);

	flowp = oaclient_identity_get_flow(ident);
	if (flowp) {
	    flow = find_strncase_index_inlist(SUPPORTED_FLOWS , flowp, strlen(flowp));
	}
	/*
	 * OK, now we do the right thing based on what our previous state was.
	 */
	switch (state) {
	case OACLIENT_STATE_TOKEN:
	    /* Nuke the current cred and update. */
	    oaclient_credential_set_token(*cred, NULL);
	    oaclient_cache_update(ctx, endpoint, ident, *cred);
	    return OAC_OK;
	case OACLIENT_STATE_REFRESHED:
	    expiry = oaclient_credential_get_expiry(*cred);
	    if ((OAC_OK == result) && 
		((time(NULL) + OACLIENT_EXPIRY_SKEW) > expiry)) {
		// it might have been a while...  if so, refresh again.
		// but don't try this if we just refreshed above and failed.
		/* Nuke the current cred and update. */
		oaclient_credential_set_token(*cred, NULL);
		oaclient_cache_update(ctx, endpoint, ident, *cred);
		return OAC_OK;
	    } else {
		// if the token should be current, nuke the session and cred.
		oaclient_cache_forget_credential(ctx, *cred);
		oaclient_cache_update(ctx, endpoint, ident, *cred);
		return OAC_OK;
	    }
	    break;

	case OACLIENT_STATE_UNKNOWN:
	case OACLIENT_STATE_DISCOVER:
	case OACLIENT_STATE_AUTHENTICATED:
	    // I'd like to know here how recently the last authorization happened.
	    // This would let me figure out whter soemthing is fundamentally broken,
	    // as a proxy use the token expiry time.  If we're getting this case
	    // when we think the token should be valid then we're hosed.
	    expiry = oaclient_credential_get_expiry(*cred);
	    if (OACLIENT_STATE_AUTHENTICATED != state ||
		(NULL ==  oaclient_credential_get_token(*cred) ||
		 (time(NULL) + OACLIENT_EXPIRY_SKEW) > expiry)) {
		// if the token should be current, nuke the session and cred.
                oaclient_cache_forget_credential(ctx, *cred);
                oaclient_cache_update(ctx, endpoint, ident, *cred);
                return OAC_OK;
	    } else {
		// re-authenticating is probably pointless
		return OAC_FAIL;
	    }
	    break;
	default:
	    return OAC_FAIL;
	}
    } else {
	/*
	 * OK, no discovery means try to bootstrap.
	*/
	/* Endpoint -> Credential? */
	result = oaclient_get_credential_for_endpoint(&tmpcred, ctx, endpoint);

	switch (result) {
	case OAC_OK:
	    oaclient_ctx_set_state(ctx, OACLIENT_STATE_TOKEN);
	    // if the token should be current, nuke the session and cred.
	    oaclient_cache_forget_credential(ctx, *cred);
	    oaclient_cache_update(ctx, endpoint, ident, *cred);
	    return OAC_OK;
	    if (time(NULL) > oaclient_credential_get_expiry(tmpcred)) {
		oaclient_cache_forget_credential(ctx, *cred);
		result = tunnel_refresh(ctx, *cred, flow,  NULL);	    
	    }
	    if (OAC_OK != result) {
		return tunnel_request_discovery(ctx, endpoint, &out);
	    }
	    break;
	case OAC_FAIL:
	    /* 
	    ** If we don't have anything stored... need basic doscovery info. 
	    ** 
	    ** Theres a decision to take here...  do we actually need to know the 
	    ** preferred scope and token type from the endpoint.  We probably
	    ** want this, but I'm not sure.
	    */
	    result = tunnel_request_discovery(ctx, endpoint, &out);	
	    if (OAC_OK == result) {
		oaclient_ctx_set_state(ctx, OACLIENT_STATE_UNKNOWN);
		*payload = out;
	    } 
	    return result;
	default:
	    return result;
	}
    }

    /* If we get here we should have a good credential to use. */
    if (OAC_OK == result) {
	result = tunnel_auth_credentialed(ctx, *cred, endpoint, &out);
    }

    if (OAC_OK == result) {
	*payload = out;
    } 
    return result;
}

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
			const char *password)
{
    const char *token;
    int result;

    /* 
     * Do we have what we need? 
     *
     * Have we had a token before? If so then we need to purge it.
     *
     * XXXXXXX How do we discover if we have bad discovery info?
     */
    token = oaclient_credential_get_token(cred);
    if (token) { 
      oaclient_credential_reset(cred);
    }

    /* OK, go do it */    
    switch (flow) {
    case FLOW_YDN:
	result = tunnel_ydn_authenticate(ctx, cred, ep, password);
	break;
    case FLOW_OAUTH2:
	result = tunnel_oauth2_authenticate(ctx, cred, ep, password);
	break;
    case FLOW_OAUTH:
	// OAuth 1.0 also doesn't have a simple password authorization,
	// and this doesn't support browser auth.  (Browser auth for
	// local applications will mean somethign like registering a URI
	// handler locally for something like "oauthcallback:" which
	// may or may not be worth it in the long run.  Local clients
	// probably want OAuth 2.0 anyway.
    default:
	return OAC_FAIL;
    }


    return result;
}

/**
 * tunnel_refresh
 *
 * Wrapper for the refresh logic.  Picks the right flow and
 * uses that.  Takes a rock to throw to the YDN flow if needed.
 */
int tunnel_refresh(struct oaclient_ctx *ctx,
		   struct oaclient_credential *cred,
		   int flow,
		   const char *rock)
{
    const char *token;
    int result;

    /* 
     * Do we have what we need? Have we had a token before?
     * If so then we can in fact try a refresh.
     */
    token = oaclient_credential_get_token(cred);
    if (!token)
	return OAC_NEED_INFO;   // this means do an auth.
    
    /* Try a refresh */
    result = OAC_FAIL;
    switch (flow) {
    case FLOW_YDN:
	result = tunnel_ydn_refresh(ctx, cred, NULL);
	break;
    case FLOW_OAUTH2:
	result = tunnel_oauth2_refresh(ctx, cred);
	break;
    case FLOW_OAUTH:
	// OAuth 1.0 doesn't have a "refresh" concept. Set up for new 
	// authorization.  
	//
	// This is really a stub because we don't have a non-username/
	// password auth in OAuth 1.0a.
	//
	// result = OAC_FAIL;
    default:
	return OAC_FAIL;
    }

    return result;
}

/** 
 * curl related utilities
 *
 * Small stuff we need for parsing/processing in curl.
 */

/*
** tunnel_curl_write_cb
**
**   Called once per header line.  Allocates space for the body of the
**   returned data.  Parses the HTTP result code.
**
** tunnel_curl_write_cb
**
** Catches the data read by CURL
**
** XXXXXXXX Note that we're assuming that we'll have Content-Length.
** This probably needs to be fixed. 
*/
size_t tunnel_curl_hdr_cb(void *buffer, size_t size, 
				  size_t nmemb, void *userp) {
  curl_data_t *curldata = userp;
  int sizeN = size * nmemb;
  char *buff = buffer;

  if (0 == strncmp("HTTP/1.1 ", buff, 8)) {
    if (curldata->data) {
      free(curldata->data);
      memset(curldata, 0, sizeof(curl_data_t));
    }
    curldata->code = atoi(buff+8);
  }

  if (0 == strncmp("Content-Length: ", buff, 16)) {
    curldata->size = atoi(buff+16);
    curldata->data = malloc(curldata->size +1);
    if (NULL == curldata->data) return 0;
    memset(curldata->data, 0, curldata->size);
  }

  return sizeN;
}

size_t tunnel_curl_write_cb( void *buffer, size_t size, size_t nmemb, void *userp) {
  curl_data_t *curldata = userp;
  char *buff = buffer;
  int sizeN = size * nmemb;
  int newsize = 0, minsize;

  /* make sure we have space for the new data */
  if (NULL == curldata->data || 
      0 == curldata->size || 
      sizeN > (curldata->size - curldata->offset - 1)) {
    for (minsize = curldata->offset + sizeN; 
	 newsize < minsize; 
	 newsize += 4096);
    curldata->data = realloc(curldata->data, newsize);
  }

  if (curldata->data) {
    strncpy(curldata->data + curldata->offset, buff, sizeN);
    curldata->offset += sizeN;
    curldata->data[sizeN] = 0;
  }

  return sizeN;
}

/*
 * Curl setup macros.
 */
#define CURL_SETUP(easyhandle)   curl_easy_setopt(easyhandle, CURLOPT_POST, 1);	\
    curl_easy_setopt(easyhandle, CURLOPT_HEADER, 0);                    \
    curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, tunnel_curl_hdr_cb); \
    curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, tunnel_curl_write_cb); \
    curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, &curldata);		\
    curl_easy_setopt(easyhandle, CURLOPT_HEADERDATA, &curldata);

#define CURL_GET_SETUP(easyhandle)   curl_easy_setopt(easyhandle, CURLOPT_POST, 0);	\
    curl_easy_setopt(easyhandle, CURLOPT_HEADER, 0);                    \
    curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, tunnel_curl_hdr_cb); \
    curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, tunnel_curl_write_cb); \
    curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, &curldata);		\
    curl_easy_setopt(easyhandle, CURLOPT_HEADERDATA, &curldata);


/*
 * t_curl_getjson
 *
 * Probably used for discovery stuff, this takes a URL to fetch
 * and returns the parse JSON object reference.  Caller needs to 
 * free it.
 */
int t_curl_getjson(const char *target, json_t **jobj)
{
  int result=OAC_OK;

  CURL *easyhandle = curl_easy_init();
  curl_data_t curldata;
  json_error_t jerror;

  
  /* Basic Curl setup */
  memset(&curldata, 0, sizeof(curldata));
  CURL_GET_SETUP(easyhandle);

  /* Set the form info */  
  curl_easy_setopt(easyhandle, CURLOPT_URL, target); 
  curl_easy_perform(easyhandle); /* post away! */ 

  /*
   * OK, load what we got and see if it worked.
   */
  if (!curldata.data)
      return OAC_NO_DISCOVERY;
  *jobj = json_loads(curldata.data, &jerror);

  if (!*jobj)
      return OAC_FAIL;
    
  /* cleanup */
  free(curldata.data);
  curl_easy_cleanup(easyhandle);
  
  return result;
}

/*
 * t_get_hostmeta
 */
int t_get_hostmeta(const char *host, json_t **jobj)
{
    int retval = OAC_OK;
    char *fmt = "http://%s/.well-known/host-meta.json";   /// XXXXXXX This SHOULD use HTTPS
    char *url;

    if (!host || !*host || !jobj) return OAC_FAIL;

    /* Request with a null credential, we send host and port in case the server cares. */
    asprintf(&url, fmt, host);
    if (NULL == url)
        return OAC_NOMEM;

    retval = t_curl_getjson((const char*)url, jobj);

    free(url);
    return retval;
}


/*
** t_discover
**
** In the context, which should now have an endpoint, do WebFinger
** discovery.
**
** Now we need perhaps to discover about the endpoint.
** Service based discovery will be entertaining here.  We need to:
**
** 1) hit the right https://$domain/.well-known/host-meta or .json version
** 2) parse out the lrdd endpoint?  right now we're just using hote meta
** 3) hit the lrdd endpoint?
** 4) parse for the rel types we need
** 5) cache them for later
**
** For a generic client we may have some "fun", we'll have to do a several
** step process to figure out where to start.
**
** 1) look at the username, if it has a domain component discover that domain
** 2) look at the hostname, then try discovering based on that.  May have to
**    end up with user@host built up.  What do we do if user@host doesn't 
**    have LRDD? Try shortening the hostname and retry?  Or do we do that first
*/

int t_discover(struct oaclient_ctx *ctx,
	       struct oaclient_endpoint *where,
	       struct oaclient_identity *ident) {
    int result = OAC_OK;
    const char *host = oaclient_endpoint_get_hostname(where);
    const char *user = oaclient_endpoint_get_username(where);
    const char *dhost;
    char *here;

    json_t *jobj;


    if (!host || !user || !*host || !*user) return OAC_BADPROT;

    /*
    ** If we have an @ then derive the discovery hostname from username.
    **
    ** XXXXXXX At some point this might need to become discovering from 
    ** the hostname for the MX record for the email ID.
    */
    if ((here = rindex(user, '@'))) {
	dhost = here +1;
    } else {
	dhost = host;
    }

    if (OAC_OK != (result = t_get_hostmeta(host, &jobj))) 
	return result;

    /* Now take the JSON we got and get stuff from it. */
    result = t_extract_oauth2_rel(ctx, ident, jobj); 

    return result;
}


/*
 * tunnel_oauth2_parse_tokens
 *
 * Take the returned data from an OAuth 2 token request and parse
 * out th tokens into the provided cred.
 */
int tunnel_oauth2_parse_tokens(struct oaclient_ctx *ctx,
			       struct oaclient_credential *cred,
			       curl_data_t *curldata)
{
  int result=OAC_OK;
  const char *token_type;
  json_t *jobj, *jtmp;
  json_error_t jerror;


  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.  That's done by the caller.
  */
  switch (curldata->code) {
  case 401:
    /* indicate password failure */
    result = OAC_AUTH_FAIL;
    break;
  case 200:
    /* A 200 OK in this case contains in the example
    **
    ** HTTP/1.0 200 OK
    ** Content-Type: text/plain
    ** 
    ** RequestToken=jkdjkljsdflkjsfkjasldfkjsklfj0239423904jsdklfjklsdfjlasdkf
    **
    */
    //    if (curldata->data && (NULL != (here = strstr(curldata->data, "\r\n\r\n")))) {
    //      here += 4;
    jobj = json_loads(curldata->data, &jerror);
    if (!jobj) 
      return OAC_FAIL;
    /* */

    jtmp = json_object_get(jobj, "token_type");
    if (jtmp) {
      token_type = json_string_value(jtmp);
      oaclient_credential_set_scheme(cred, token_type);
    } else {
      json_object_clear(jobj);
      return OAC_BADPROT;
    }

    jtmp = json_object_get(jobj, "access_token");
    if (jtmp) {
      oaclient_credential_set_token(cred, json_string_value(jtmp));
    } else {
      json_object_clear(jobj);
      return OAC_BADPROT;
    }
    /* XXXXXXX need to add MAC token support here at some point */

    /* returned refresh  token  is optional */
    jtmp = json_object_get(jobj, "refresh_token");
    if (jtmp) {
      oaclient_credential_set_session(cred, json_string_value(jtmp));
    }
    /* returned scope is optional */
    jtmp = json_object_get(jobj, "scope");
    if (jtmp) {
      oaclient_identity_set_scope(cred->ident, json_string_value(jtmp));
    }
    /* returned expiry is optional */
    jtmp = json_object_get(jobj, "expires_in");
    if (jtmp) {
      oaclient_credential_set_expiry(cred, json_integer_value(jtmp));
    }
    json_object_clear(jobj);
    // implicit result = OAC_OK;

    break;
  default:
    /*    snprintf(errbuff, ERRBUFFLEN, 
	  "Remote auth server returns HTTP code %d", text->curl.code);
    */
    result = OAC_FAIL;
  }
    
  /* cleanup */
  memset(curldata->data, 0, curldata->size);
  free(curldata->data);  
  memset(curldata, 0, sizeof(*curldata));
  
  return result;
}


/**
 * tunnel_oauth2_authenticate
 *
 * Do an Oauth 2 password credential authorization.  Note that for pasword
 * grate we do NOT use the authorization URL, we use the token URL.
 */
#define OAUTH2_TOKEN_REQ_FMT   "grant_type=password&client_id=%s&client_secret=%s&" \
                               "username=%s&password=%s"

int tunnel_oauth2_authenticate(struct oaclient_ctx *ctx,
			       struct oaclient_credential *cred,
			       struct oaclient_endpoint *ep,
			       const char *password)
{
  struct oaclient_identity *ident = oaclient_credential_get_identity(cred);

  int result=OAC_OK;

  CURL *easyhandle = curl_easy_init();
  char *reqfmt = OAUTH2_TOKEN_REQ_FMT;

  char *safe_user, *safe_password;
  char *postbuffer;
  curl_data_t curldata;

  memset(&curldata, 0, sizeof(curldata));
  if (!ep->username || !password) 
      return OAC_FAIL;

  safe_user = curl_easy_escape(easyhandle, ep->username, 0);
  safe_password = curl_easy_escape(easyhandle, password, 0);

  /* Basic Curl setup */
  CURL_SETUP(easyhandle);

  /* create the post data for the curl call. */
  if (-1 == asprintf(&postbuffer, reqfmt, ydn_consumer_key, ydn_consumer_secret, 
		     safe_user, safe_password)) {
    curl_easy_cleanup(easyhandle);
    curl_free(safe_user);
    curl_free(safe_password);
    return OAC_NOMEM;
  }
  /* Set the form info */  
  curl_easy_setopt(easyhandle, CURLOPT_URL, ident->refresh_url); 
  curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
  curl_easy_perform(easyhandle); /* post away! */ 

  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.  That's done by the caller.
  */
  result = tunnel_oauth2_parse_tokens(ctx, cred, &curldata);
    
  /* cleanup */
  free(postbuffer);
  free(curldata.data);
  curl_free(safe_user);
  curl_free(safe_password);
  curl_easy_cleanup(easyhandle);
  
  return result;
}
/**
 * tunnel_oauth2_refresh
 *
 * Do an Oauth 2 credential refresh.
 *
 * Note that we have:
 * 
 * -   A fixed client_id & secret right now
 * -   A dummy callback uri.  Not sure why we need it, but Yahoo OAuth 2 seems
 *     to require it.
 */
#define OAUTH2_TOKEN_REFRESH_FMT  "grant_type=refresh_token&client_id=%s&" \
                                  "client_secret=%s&refresh_token=%s&" \
                                  "redirect_uri=http://localhost/callback" \


int tunnel_oauth2_refresh(struct oaclient_ctx *ctx,
			  struct oaclient_credential *cred)
{
  struct oaclient_identity *ident = oaclient_credential_get_identity(cred);

  int result=OAC_OK;

  CURL *easyhandle = curl_easy_init();
  char *reqfmt = OAUTH2_TOKEN_REFRESH_FMT;

  char *postbuffer;
  curl_data_t curldata;

  memset(&curldata, 0, sizeof(curldata));

  /* Basic Curl setup */
  CURL_SETUP(easyhandle);

  /* create the post data for the curl call. */
  if (-1 == asprintf(&postbuffer, reqfmt, ydn_consumer_key, 
  		     ydn_consumer_secret, cred->session)) {
    curl_easy_cleanup(easyhandle);
    return OAC_NOMEM;
  }
  /* Set the form info */  
  curl_easy_setopt(easyhandle, CURLOPT_URL, ident->refresh_url); 
  curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
  curl_easy_perform(easyhandle); /* post away! */ 

  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.  That's done by the caller.
  */
  result = tunnel_oauth2_parse_tokens(ctx, cred, &curldata);
      
    
  /* cleanup */
  free(postbuffer);
  free(curldata.data);
  curl_easy_cleanup(easyhandle);
  
  return result;
}

/**
 * tunnel_ydn_authenticate
 *
 * Yahoo! YDN specific "Direct Oauth" authorization flow support.
 *
 * First get the "PART" token  and then turn that in for the cred.
 *
 * XXXXXXX We have an open issue with YDN, to whit: what client ID will we be using?  
 * For the moment we'll use the test YDN App, but this will ned to get figured out.
 */
#define ERRBUFFLEN = 4096;
#define YDN_PART_REQ_FMT   "oauth_consumer_key=%s&login=%s&passwd=%s"

#define YDN_TOKEN_REQ_FMT  "oauth_consumer_key=%s&oauth_signature=%s%%26%s&" \
                           "oauth_signature_method=PLAINTEXT&oauth_nonce=%d&" \
                           "oauth_timestamp=%d&oauth_version=1.0&oauth_token=%s"

#define YDN_TOKEN_REFRESH_FMT  YDN_TOKEN_REQ_FMT "&oauth_session_handle=%s&"

#define YDN_PART_TOKEN_TAG    "RequestToken"
#define YDN_OAUTH_TOKEN_TAG   "oauth_token"
#define YDN_OAUTH_SECRET_TAG  "oauth_token_secret"
#define YDN_OAUTH_SESSION_TAG "oauth_session_handle"
#define YDN_OAUTH_EXPIRES_TAG "oauth_expires_in"



int tunnel_ydn_authenticate(struct oaclient_ctx *ctx,
			    struct oaclient_credential *cred,
			    struct oaclient_endpoint *ep,
			    const char *password)
{
  struct oaclient_identity *ident = oaclient_credential_get_identity(cred);

  int result=OAC_OK;

  CURL *easyhandle = curl_easy_init();
  char *reqfmt = YDN_PART_REQ_FMT;

  char *safe_user, *safe_password;
  char *postbuffer, *ydnPART=NULL;
  curl_data_t curldata;

  memset(&curldata, 0, sizeof(curldata));
  if (!ep->username || !password) 
      return OAC_FAIL;

  safe_user = curl_easy_escape(easyhandle, ep->username, 0);
  safe_password = curl_easy_escape(easyhandle, password, 0);

  /* Basic Curl setup */
  CURL_SETUP(easyhandle);

  /* create the post data for the curl call. */
  if (-1 == asprintf(&postbuffer, reqfmt, ydn_consumer_key, safe_user, safe_password)) {
    curl_easy_cleanup(easyhandle);
    curl_free(safe_user);
    curl_free(safe_password);
    return OAC_NOMEM;
  }
  /* Set the form info */  
    curl_easy_setopt(easyhandle, CURLOPT_URL, ident->initiate_url); 
    curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
    //  TOKEN_CURL_SETUP(ident->initiate_url, postbuffer, tunnel_curl_hdr_cb, 
    //	   tunnel_curl_write_cb, &curldata);
  curl_easy_perform(easyhandle); /* post away! */ 

  /* once we have an token we don't want the password anymore */
  DEBUG_PRINT("Fetch PART");
  DEBUG_PRINTF(postbuffer);
  DEBUG_PRINTF(curldata.data);
  free(postbuffer);

  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.  That's done by the caller.
  */
  switch (curldata.code) {
  case 401:
    /* indicate password failure */
    result = OAC_AUTH_FAIL;
    break;
  case 200:
    /* A 200 OK in this case contains in the example
    **
    ** HTTP/1.0 200 OK
    ** Content-Type: text/plain
    ** 
    ** RequestToken=jkdjkljsdflkjsfkjasldfkjsklfj0239423904jsdklfjklsdfjlasdkf
    **
    */
      if (curldata.data) {
	  ydnPART = find_post_variable(curldata.data, YDN_PART_TOKEN_TAG);
	  if (!ydnPART) {
	      result = OAC_BADPROT;
	  }
      }
      break;
  default:
      /*    snprintf(errbuff, ERRBUFFLEN, 
	    "Remote auth server returns HTTP code %d", text->curl.code);
      */
      result = OAC_FAIL;
  }

  /*
   * If we are OK to proceed, get the credentials. 
   */
  if (OAC_OK == result) {
      result = tunnel_ydn_refresh(ctx, cred, ydnPART);
  }
  
  /* cleanup */
  free(ydnPART);
  free(curldata.data);
  curl_free(safe_user);
  curl_free(safe_password);
  curl_easy_cleanup(easyhandle);
  
  return result;
}

/*
 * tunnel_ydn_refresh
 *
 * Called when we have a YDN style token and need to refresh it. It's 
 * much the same as the last half of above, might end up being a simple
 * refactoring....
 *
 * Yahoo! YDN specific "Direct Oauth" token refresh support..
 *
 * XXXXXXX We have an open issue with YDN, to whit: what client ID will we be using?  
 * For the moment we'll use the test YDN App, but this will ned to get figured out.
 */
int tunnel_ydn_refresh(struct oaclient_ctx *ctx,
		       struct oaclient_credential *cred,
		       const char *ydnPART)
{
    struct oaclient_identity *ident = oaclient_credential_get_identity(cred);

    int result = OAC_OK, result2;
    int nonce = random();

    CURL *easyhandle = curl_easy_init();

    char *postbuffer, *reqfmt;
    curl_data_t curldata;

    memset(&curldata, 0, sizeof(curldata));

    /* Basic Curl setup */
    CURL_SETUP(easyhandle);

    /* */
    DEBUG_PRINT("ydn refresh/exchange PART for token.");
    if (ydnPART) DEBUG_PRINTF(ydnPART);
    /* create the post data for the curl call. */
    if (ydnPART) {	
	reqfmt = YDN_TOKEN_REQ_FMT;
	result2 = asprintf(&postbuffer, reqfmt, 
			   ydn_consumer_key, ydn_consumer_secret, "",
			   nonce, (int)time(NULL), ydnPART);
    } else {
	reqfmt = YDN_TOKEN_REFRESH_FMT;
	result2 = asprintf(&postbuffer, reqfmt, 
			   ydn_consumer_key, ydn_consumer_secret, cred->secret,
			   nonce, (int)time(NULL), cred->token, cred->session);
    }
    if (-1 == result2) {
	free(curldata.data);
	curl_easy_cleanup(easyhandle);
	return OAC_NOMEM;
    }
    /* Set the form info */      
    curl_easy_setopt(easyhandle, CURLOPT_URL, ident->refresh_url); 
    curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
    
    curl_easy_perform(easyhandle); /* post away! */ 
    
    DEBUG_PRINTF(postbuffer);  
    DEBUG_PRINTF(curldata.data);  
    free(postbuffer);
    // Now parse out the things we need.
    if (curldata.data && curldata.data[0]) {	
	char *parse_token   = find_post_variable(curldata.data, YDN_OAUTH_TOKEN_TAG);
	char *parse_secret  = find_post_variable(curldata.data, YDN_OAUTH_SECRET_TAG);
	char *parse_session = find_post_variable(curldata.data, YDN_OAUTH_SESSION_TAG);
	char *parse_expires = find_post_variable(curldata.data, YDN_OAUTH_EXPIRES_TAG);
    
	if (parse_token && parse_secret && parse_session && parse_expires) {
	    // We can proceed
	    oaclient_credential_set_token(cred, parse_token);
	    oaclient_credential_set_secret(cred, parse_secret);
	    oaclient_credential_set_session(cred, parse_session);
	    oaclient_credential_set_expiry(cred, atoi(parse_expires));
	} else {
	    result = OAC_FAIL;
	}
	free(parse_token);
	free(parse_secret);
	free(parse_session);
	free(parse_expires);
    }
    
    /* cleanup */
    free(curldata.data);
    curl_easy_cleanup(easyhandle);

    return result;
}


/** 
 * parser utilities
 *
 * Small stuff we need for parsing/validation.
 */
int is_valid_hostname(const char *in) {
    regex_t _preg;
    regex_t *preg = &_preg;
    int result;

    if (NULL == in || 0 == *in) return OAC_FAIL;
    
    result = regcomp(preg, "[^-.a-z0-9]|[.][.]", REG_ICASE | REG_NOSUB | REG_EXTENDED);
    result = regexec(preg, in, 0, NULL, 0);
    regfree(preg);

    if (result == REG_NOMATCH) return OAC_OK;

    return OAC_FAIL;
}


/*
 * This one finds and returns a new string for the value of the
 * post variable in the haystack.
 *
 * This is used in the YDN flow stuff.
 */
char *find_post_variable(char *haystack, char *name)
{
    char *result = NULL;
    char *apos=NULL, *bpos, *cpos, *padded_name;
    int len = strlen(name);

    asprintf(&padded_name, "&%s=", name);

    if (!padded_name)
	return NULL;

    if ((!strncmp(haystack, name, len)) &&
	'=' == haystack[len]) {
	apos = haystack + len + 1;
    } else {
	apos = strstr(haystack, padded_name);
	if (!apos) {
	    free(padded_name);
	    return NULL;
	}
	apos += len + 2;
    }
    bpos = strchr(apos, '&');
    cpos = strchr(apos, '\n');
    if (!bpos && !cpos) {
	result = strdup(apos);
    } else {
      if (bpos && (NULL == cpos || bpos<cpos)) {
	    result = strndup(apos, bpos - apos);
	} else {
	    result = strndup(apos, cpos - apos);
	}
    }

    free(padded_name);
    return result;
}

/*
** Used in the scanning of what capabilities we support.
 */
const char *find_strncase_inlist(const char*list[], char *needle, int len)
{
    const char *this;
    int i=0;
    for (this = list[i]; this; this=list[++i]) {
	if (0 == strncasecmp(this, needle, len))
	    break;
    }
    return this;
}

int find_strncase_index_inlist(const char*list[], const char *needle, int len)
{
    const char *this;
    int i=0;
    if (!list || !needle)
	return -1;
    for (this = list[i]; this; this=list[++i]) {
	if (0 == strncasecmp(this, needle, len))
	    return i;
    }
    return -1;
}


/*
** Extract OAUTH2 related data from the JSON and stuff it into the endpoint info.
**
** XXXXXXXX NOte that we only support OAuth2 Bearer tokens at this time.
*/
#define PARSE_LINK_OA2AUTH        "oauth2-authorize"
#define PARSE_LINK_OA2TOKEN       "oauth2-token"

int t_extract_oauth2_rel(struct oaclient_ctx *ctx,
			 struct oaclient_identity *who,
			 json_t *jobj) {
    int result = OAC_OK;
    json_t *this, *links, *rel, *href, *grants, *tokens;
    int i, got_token = 0, got_auth=0 , max = json_object_size(jobj);
    const char *name, *url, *grant_types, *token_types;


    // First get the links object out
    links = json_object_get(jobj, "links");
    if (NULL == links) 
	return OAC_FAIL;

    // Now iterate through and find the stuff we need.
    for (i=0; i<max && !(got_token && got_auth); i++) {
	this = json_array_get(links, i);
	rel = json_object_get(this, "rel");
	if (NULL == rel) continue;
	name = json_string_value(rel);
	if (NULL == name) continue;

	// Get the URL we might gare about, skip it if not found.
	href =  json_object_get(this, "href");
	if (NULL == href) continue;
	url = json_string_value(href);
	if (NULL == url) continue;

	// Is this a droid we're looking for?
	if (0 == strcmp(name, PARSE_LINK_OA2AUTH)) {
	    result = oaclient_identity_set_authorization_url(who, url);
	    if (OAC_OK != result)
		return result;
	    got_auth=1;
	    continue;
	}
	// Is this a droid we're looking for?
	// If so we have some more stuff to check for, the 'password' grant type is required.
	if (0 == strcmp(name, PARSE_LINK_OA2TOKEN)) {
	    grants = json_object_get(this, "grant-types");
	    if (NULL == grants) continue;
	    grant_types = json_string_value(grants);
	    if (NULL == grant_types) continue;
	    if (!strcasestr(grant_types, "password")) continue;

	    tokens = json_object_get(this, "token-types");
	    if (NULL == tokens) continue;
	    token_types = json_string_value(tokens);
	    if (NULL == token_types) continue;
	    if (!strcasestr(token_types, "bearer")) continue;

            result = oaclient_identity_set_refresh_url(who, url);
            if (OAC_OK != result)
                return result;
            got_token=1;
            continue;
	}
    }

    if (got_token && got_auth)
	return OAC_OK;

    return OAC_FAIL;
}


#define PARSE_LINK_OAINIT    "oauth-initiate"
#define PARSE_LINK_OAAUTH    "oauth-authorize"
#define PARSE_LINK_OATOKEN   "oauth-token"

/**
 * tunnel_request_discovery
 *
 * Generates the SASL payload to request discovery information.
 */
/*
** N.B. that post, path, and query are reserved for future use.
*/
#define KV_SEPCHAR              0x1                            
#define KV_SEP                  "\x1"                            
typedef enum {KV_HOST, KV_PORT, KV_AUTH, KV_POST, KV_PATH, KV_QUERY} KVINDEX_ENUM;
const char* KV_STRINGS[] = {"host", "port", "auth", "post", "path", "query"};

#define TUNNEL_REQ_FMT          ("auth=%s" KV_SEP "host=%s" KV_SEP "port=%d" KV_SEP KV_SEP)


int tunnel_request_discovery(struct oaclient_ctx *ctx,
                             struct oaclient_endpoint *where,
                             char **payload)
{
    // const char *name = oaclient_endpoint_get_username(where);
    // const char *path = oaclient_endpoint_get_path(where);

    const char *host = oaclient_endpoint_get_hostname(where);
    int  port = oaclient_endpoint_get_port(where);

    char *outp;

    *payload = NULL;

    if ((!payload) || !host || port <= 0 || (OAC_OK != is_valid_hostname(host)))
	return OAC_FAIL;


    /* Request with a null credential, we send host and port in case the server cares. */
    asprintf(&outp, TUNNEL_REQ_FMT, "", host, port);
    if (NULL == outp)
	return OAC_NOMEM;

    *payload = outp;

    return OAC_OK;
}


#define HTTP_RPY_1_1           "HTTP/1.1 "
#define WWW_AUTHENTICATE       "\r\nWWW-Authenticate: "

/**
 * tunnel_parse_discovery
 *
 * Parse an JSON blob which should contain discovery information.
 */
int tunnel_parse_discovery(struct oaclient_ctx *ctx,
			     struct oaclient_credential *cred,
                             const char *payload)
{
    struct oaclient_identity *who = cred->ident;
    int ecode;
    char *tmpstr, *valstr, *eov, *scheme;
    const char *schemes, *scope=NULL;
    enum supported_scheme knownscheme = SCHEME_UNKNOWN;

    int schemelen, limit;

    json_t *jobj, *jtmp;
    json_error_t jerror;


    /*
     * Sanity check
     */
    if (NULL == payload || 0 == payload[0])
	return OAC_BAD_PARAM; 
    
    /* Grab the JSON */ 
    jobj = json_loads(payload, &jerror);
    if (!jobj) 
      return OAC_FAIL;

    /* Get error and scope */

    jtmp = json_object_get(jobj, "status");
    if (jtmp) {
      ecode = json_integer_value(jtmp);
    } else {
      json_object_clear(jobj);
      return OAC_BADPROT;
    }

    jtmp = json_object_get(jobj, "schemes");
    if (jtmp) {
      schemes = json_string_value(jtmp);
    } else {
      json_object_clear(jobj);
      return OAC_BADPROT;
    }

    jtmp = json_object_get(jobj, "scope");
    if (jtmp) {
      scope = json_string_value(jtmp);
      oaclient_identity_set_scope(cred->ident, scope);
    } 

    /* 
    ** Now, having the error code and string we can do work. Being
    ** detail oriented here for supporting new returns that might 
    ** creep in.
    **
    ** N.B. that the 400 return code is actually handled at the SASL
    ** level, we don't need it here.
    */
    switch (ecode) {
    case 401: /* invalid-token, unsupported, and expired-token */
    case 403: /* right now this is only insufficient-scope */
      /* 
      ** So we have an invalid token or scope, which is what we can deal with.
      */
	break;
    default:
      return OAC_BADPROT;
    }

    /*
    ** We need to grab the authorization scheme out of the discovery info.
    */
    if (NULL == (tmpstr = strdup(schemes))) {
        return OAC_NOMEM;
    }
    
    scheme = tmpstr;
    eov = tmpstr;
    limit = strlen(scheme);
    while (eov && (scheme < (tmpstr + limit))) {
	eov = index(scheme, ' ');	
	if (eov) {   // replace the first space if there is one
	    *eov = 0;
	}
	/* Did we find one we know? */
	schemelen = strlen(scheme);
	knownscheme = find_strncase_index_inlist(SUPPORTED_SCHEMES, scheme, schemelen);
	if (SCHEME_UNKNOWN != knownscheme)
	    break;
	
	/* check the next scheme if there is one. */
	if (eov) {
	    scheme = eov + 1;
	}
    } // endwhile 


    /* Do we have a scheme we're willing to support?  */
    switch (knownscheme) {
    case SCHEME_UNKNOWN:
	/* sanity check, need to have found something. */
	free(tmpstr);
 	return OAC_NO_SCHEMES;           
    case SCHEME_OAUTH:
        oaclient_identity_set_flow(who, SUPPORTED_FLOWS[FLOW_YDN]);
	break;
    case SCHEME_BEARER:
        oaclient_identity_set_flow(who, SUPPORTED_FLOWS[FLOW_OAUTH2]);
	break;
    default:
	free(tmpstr);
	return OAC_NO_SCHEMES;
    }

    /* take what we found and populate stuff */

    valstr = local_strndup(scheme, schemelen);
    oaclient_credential_set_scheme(cred, valstr);
    free(valstr);
    
    if (scope) {
	oaclient_identity_set_scope(who, valstr);
    }

    free(tmpstr);
    return OAC_OK;
}

/**
 *
 *
 */
int tunnel_auth_credentialed(struct oaclient_ctx *ctx,
			     struct oaclient_credential *cred,
                             struct oaclient_endpoint *ep,
			     char **out)
{
    enum supported_scheme scheme;
    const char *schemep = oaclient_credential_get_scheme(cred);
    
    if (!schemep)
	return OAC_FAIL;

    scheme = find_strncase_index_inlist(SUPPORTED_SCHEMES, schemep, strlen(schemep));
    switch (scheme) {
    case SCHEME_BEARER:
	return tunnel_auth_bearer(ctx, cred, ep, out);
    case SCHEME_MAC:
	return tunnel_auth_mac(ctx, cred, ep, out);
    case SCHEME_OAUTH:
	return tunnel_auth_oauth(ctx, cred, ep, out);
    default:
	return OAC_FAIL;
    }

    return OAC_FAIL;
}
/*
 *
 */

#define TUNNEL_AUTH_FMT_URL "http://%s%s"
/*
 *
 */
int tunnel_auth_fmt_url(struct oaclient_ctx *ctx,
			struct oaclient_credential *cred,
			struct oaclient_endpoint *ep,
			char **out)
{
    const char *host = oaclient_endpoint_get_hostname(ep);
    const char *path = oaclient_endpoint_get_path(ep);
    int  port = oaclient_endpoint_get_port(ep);

    char hostbuf[256], *outp;
    const char *hostp;


    if ((!out) || !host || port <= 0)
	return OAC_FAIL;

    *out = NULL;

    if (NULL == path || !path[0]) {
	path = "/";
    }

    if (port == 0) {
	hostp = host;
    } else {
	hostp = hostbuf;
	if (sizeof(hostbuf) == snprintf(hostbuf, sizeof(hostbuf), "%s:%d", host, port))
	    return OAC_FAIL;
    }

    asprintf(&outp, TUNNEL_AUTH_FMT_URL, hostp, path);
    if (NULL == outp)
        return OAC_NOMEM;

    *out = outp;
    return OAC_OK;
}
/*
 *
 */
int tunnel_convert_post_to_auth(char **postdata) 
{
    char *this, *that, *here, *new;
    this = *postdata;
    int count=0, len=strlen(this);

    //  count the number of variables.
    for (here = this; here; here = strchr(here, '=')) {
	here++;
	count++;
    }
    if (!count) return OAC_OK;
    
    // magic number 3 is for the 2 quotes and the space added for each item.
    len += count * 3;
    new = malloc(len+1);
    
    if (NULL == new)
	return OAC_NOMEM;

    for (this = *postdata, that = new, count = 0; count < len; count++) {
	switch (*this) {
	case '=':
	    *that++ = *this++;
	    *that++ = '"';
	    break;
	case '&':
	    *that++ = '"';
	    *that++ = ',';
	    this++;
	    break;
	case '\0':
	    *that++ = '"';
	    *that++ = '\0';
	    count = len;
	    break;
	default:
	    *that++ = *this++;
	}
    }
    free(*postdata);
    *postdata = new;
    return OAC_OK;
}

/*
 *
 */
#define TUNNEL_SASL_FMT         "auth=%s %s\x01host=%s\x01port=%d\x01\x01"

/**
 * tunnel_auth_bearer
 *
 * Generates the SASL payload to access a resource with a 
 * bearer token.
 *
 */
int tunnel_auth_bearer(struct oaclient_ctx *ctx,
		       struct oaclient_credential *cred,
		       struct oaclient_endpoint *ep,
		       char **out)
{
    char *outp;
    int result;

    const char *token = oaclient_credential_get_token(cred);
    const char *host = oaclient_endpoint_get_hostname(ep);
    int  port = oaclient_endpoint_get_port(ep);
 
    if (!out) 
	return OAC_FAIL;

    *out = NULL;

    asprintf(&outp, TUNNEL_SASL_FMT, SUPPORTED_SCHEMES[SCHEME_BEARER], token, host, port);
    if (outp) {
	*out = outp;
    } else {
	result = OAC_NOMEM;
    }

    return OAC_OK;
}

/**
 * tunnel_auth_oauth
 *
 * Generates the SASL payload to access a resource with a signed
 * OAuth 1.0a style access request for a protected resource.
 */
int tunnel_auth_oauth(struct oaclient_ctx *ctx,
		      struct oaclient_credential *cred,
		      struct oaclient_endpoint *ep,
		      char **out)
{
    char *outp=NULL, *postargs=NULL;
    char *url=NULL, *resulturl=NULL;
    int result;

    const char *token = oaclient_credential_get_token(cred);
    const char *secret = oaclient_credential_get_secret(cred);

    const char *host = oaclient_endpoint_get_hostname(ep);
    int  port = oaclient_endpoint_get_port(ep);

    if (!out)
        return OAC_FAIL;

    *out = NULL;

    if (OAC_OK != (result = tunnel_auth_fmt_url(ctx, cred, ep, &url)))
        return result;

    resulturl = oauth_sign_url2(url, &postargs, OA_HMAC, "GET",
				ydn_consumer_key, ydn_consumer_secret,
				token, secret);

    if (NULL == resulturl)
	result = OAC_FAIL;

    /* convert the postargs into Auth header format */
    result = tunnel_convert_post_to_auth(&postargs);
    if (OAC_OK != result)
	return result;
	

    /* now format the result */
    asprintf(&outp, TUNNEL_SASL_FMT, SUPPORTED_SCHEMES[SCHEME_OAUTH], postargs, host, port);

    if (outp) {
        *out = outp;
    } else {
        result = OAC_NOMEM;
    }

    /* cleanup and return */
    free(url);
    free(postargs);
    free(resulturl);
    return result;
}

/**
 * tunnel_auth_mac
 *
 * Generates the SASL payload to access a resource with a signed
 * MAC style authorization.
 */
int tunnel_auth_mac(struct oaclient_ctx *ctx,
		    struct oaclient_credential *cred,
		    struct oaclient_endpoint *ep,
		    char **out)
{
    return OAC_FAIL;
}


