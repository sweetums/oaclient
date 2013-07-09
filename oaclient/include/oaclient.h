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
#ifndef INCLUDED_OACLIENT_H
#define INCLUDED_OACLIENT_H

#include <time.h>

#ifdef __cplusplus
// commented out for ease of editing for now
// extern "C" {
#endif

// not sure if this is required
typedef unsigned int oac_u32;


/*
 * As it turns out we need a set of result things.  I wish errno was richer.
 */
#define OAC_OK                 0
#define OAC_FAIL               1
#define OAC_NOMEM              2
#define OAC_AUTH_FAIL          3
#define OAC_BAD_PARAM          4
#define OAC_NO_SCHEMES         5  // No supported schemes found to use.
#define OAC_BADPROT            6  // parsing or format failure for the protocol.
#define OAC_NEED_INFO          7  // some piece of infor needed is missing, for
                                  // example, we don't have tokesn.
#define OAC_NO_DISCOVERY       8  // Discovery failed or found no compatible endpoints.
#define OAC_NO_CRED            9  // No cached credential, and can not get one.
                                  // Not implemented yet.

#define OACLIENT_EXPIRY_SKEW  30  // 30 seconds is our window of when we're willing
                                  // to believe the token might have expired and we
                                  // should jsut re-auth/refresh, As opposed to 
                                  // assuming the worst. 
/*
 * Guidelines:
 *
 * (1) If you _create it, you must _destroy it.  (We do not currently use
 * pooled allocations, which itself is probably a bug.)
 *
 * (2) Functions that require an "out" parameter, or modify a parameter, have
 * as their first argument.  (I'm not too sure about this rule; perhaps ctx
 * should always be first.)
 *
 * (3) If a function takes more than a few arguments, or it needs to be
 * extensible, its arguments are passed as a structure.  Such a structure
 * should be declarable on the stack.
 *
 * (4) The name "rock" is used for what some libraries call a data pointer, and
 * old libraries called a cookie pointer, before "cookie" meant something else.
 * rock is something you put something under.
 *
 *
 * Currently, we do not wrap memory allocation functions, but we probably will
 * need to in the future.
 */

struct oaclient_askpass_args;
struct oaclient_credential;
struct oaclient_callbacks;
struct oaclient_ctx;
struct oaclient_endpoint;
struct oaclient_identity;

/*
 * Arguments to the user-supplied "askpass" callback.
 * 
 * These are passed as a structure to allow for future extension.
 */ 
struct oaclient_callback_args
{
    oac_u32 version;            /* version of structure */
    void *rock;                 /* user pointer (data, cookie, whatevxoer) */
    struct oaclient_ctx *ctx;   /* */
    struct oaclient_identity *who; /* who do we want the credential for? */
};
typedef int oaclient_askspass_t(struct oaclient_callback_args *, char **out);
/**
 * Callbacks for the library.
 *
 * Some calls may or may not have to ask for additional information.  In
 * particular, passwords.  These will be called when needed; the API will cache
 * credentials when it can.
 *
 * Arguments to callbacks may be passed as structures so that we can change the
 * arguments to the callback in the future.
 */
struct oaclient_callbacks
{
    oac_u32 version;
    oaclient_askspass_t *askpass;
};

/**
 * oaclient_endpoint
 *
 * An endpoint to interact with.  From this we might generate discovery information
 * or look up if we have cached information for that endpoint (discovery and 
 * credentials)
 */

int oaclient_endpoint_create(struct oaclient_endpoint **out);
void oaclient_endpoint_destroy(struct oaclient_endpoint *endpoint);

int oaclient_endpoint_set_username(struct oaclient_endpoint *endpoint, const char *username);
const char *oaclient_endpoint_get_username(struct oaclient_endpoint *endpoint);

int oaclient_endpoint_set_hostname(struct oaclient_endpoint *endpoint, const char *hostname);
const char *oaclient_endpoint_get_hostname(struct oaclient_endpoint *endpoint);

int oaclient_endpoint_set_port(struct oaclient_endpoint *endpoint, oac_u32 port);
oac_u32 oaclient_endpoint_get_port(struct oaclient_endpoint *endpoint);

int oaclient_endpoint_set_path(struct oaclient_endpoint *endpoint, const char *path);
const char *oaclient_endpoint_get_path(struct oaclient_endpoint *endpoint);


/**
 * oaclient_ctx_*
 *
 * Constructr, destructor, and accessers.
 */

enum oaclient_ctx_state {OACLIENT_STATE_UNKNOWN, 
			 OACLIENT_STATE_DISCOVER,        // sent discovery
			 OACLIENT_STATE_TOKEN,	         // sent a token
			 OACLIENT_STATE_REFRESHED,	 // sent a refreshed token
			 OACLIENT_STATE_AUTHENTICATED};  // freshly authenticated


int oaclient_ctx_create(struct oaclient_ctx **out,
                        struct oaclient_callbacks *);
void oaclient_ctx_destroy(struct oaclient_ctx *);

void *oaclient_ctx_set_rock(struct oaclient_ctx *ctx, void *rock);
void *oaclient_ctx_get_rock(struct oaclient_ctx *ctx);

void oaclient_ctx_set_state(struct oaclient_ctx *ctx, enum oaclient_ctx_state state);
enum oaclient_ctx_state oaclient_ctx_get_state(struct oaclient_ctx *ctx);

void oaclient_free(void *);
/**
 * Tunneled OAuth
 * 
 * RFC???? defines tunneled HTTP authorization in the OAuth framework
 * for non-HTTP usages.  These functions provide the needed API for getting
 * and parsing the opaque blobs (HTTP inside) that those apps like SASL need
 * to pass around to do OAuth.
 */

/* oaclient_tunnel_endpoint
 *
 * Taking an enpoint and context, return the payload to send.  If there is 
 * no stored credential then the payload is a discovery request.  If there
 * is a cached credential this returns the access request for the resource.
 *
 * If discovery information is passed in, this presumes that the cached
 * credential is no longer valid.  If the cached credential has a short term
 * access token and a durable token,  the durable token is retried before the
 * user is prompted for authorization.
 *
 * Current state is kept in the credential, and if 
 */
int oaclient_tunnel_endpoint(struct oaclient_ctx *ctx, 
			     char ** payload, 
			     struct oaclient_credential **cred,
			     struct oaclient_endpoint *endpoint, 
			     const char *discovery);

/*
 * oaclient_identity represents an identity, comprised of a username, a realm,
 * and a scope.  If any of those fields are different, that's a different
 * authenticatable identity.
 *
 * These calls may access the data store and return a credential, or they may
 * go request a credential on behalf of the user.
 */
int oaclient_identity_create(struct oaclient_identity ** /*, ... */);
int oaclient_identity_clone(struct oaclient_identity **, struct oaclient_identity *);
void oaclient_identity_destroy(struct oaclient_identity *);
int oaclient_identity_create_from_discovery(struct oaclient_identity **,
                                            struct oaclient_ctx *,
                                            const char *discovery_header_value);

const char *oaclient_identity_get_user(struct oaclient_identity *self);
const char *oaclient_identity_get_realm(struct oaclient_identity *self);
const char *oaclient_identity_get_scope(struct oaclient_identity *self);
const char *oaclient_identity_get_initiate_url(struct oaclient_identity *self);
const char *oaclient_identity_get_authorization_url(struct oaclient_identity *self);
const char *oaclient_identity_get_refresh_url(struct oaclient_identity *self);

int oaclient_identity_set_user(struct oaclient_identity *self, const char *v);
int oaclient_identity_set_realm(struct oaclient_identity *self, const char *v);
int oaclient_identity_set_scope(struct oaclient_identity *self, const char *v);
int oaclient_identity_set_initiate_url(struct oaclient_identity *self, const char *v);
int oaclient_identity_set_authorization_url(struct oaclient_identity *self, const char *v);
int oaclient_identity_set_refresh_url(struct oaclient_identity *self, const char *v);


/*
 * When oaclient wants to get _____, it may need the application to involve a browser
 * due to things like captcha.
 *
 * oaclient can call back to the application through this API.
 */ 
struct oaclient_access
{
    /*
     * oaclient calls this API when it wants a ____.  The caller must obtain the data
     * and call return_token with it.
     */ 
    void (*got_thingy)(struct oaclient_ctx *ctx,
                       void (*return_token)(struct oaclient_ctx *,
                                            void *app_rock,
                                            char *data, size_t len),
                       void *app_rock);
};

/**
 * Free resources associated with credential object.  Credential remains in
 * database.
 */
int oaclient_credential_create(struct oaclient_credential **out, struct oaclient_identity *sb /*, ... */);
int oaclient_credential_clone(struct oaclient_credential **dst,
                              struct oaclient_credential *src);
void oaclient_credential_destroy(struct oaclient_credential *);
void oaclient_credential_reset(struct oaclient_credential *self);

int oaclient_credential_set_identity(struct oaclient_credential *, struct oaclient_identity *);
struct oaclient_identity * oaclient_credential_get_identity(struct oaclient_credential *);

int oaclient_credential_update_from_discovery(struct oaclient_credential *,
					      struct oaclient_ctx *,
					      const char *discovery_header_value);

int oaclient_credential_set_token(struct oaclient_credential *, const char *);
const char * oaclient_credential_get_token(struct oaclient_credential *);

int oaclient_credential_set_secret(struct oaclient_credential *, const char *);
const char * oaclient_credential_get_secret(struct oaclient_credential *);

int oaclient_credential_set_session(struct oaclient_credential *, const char *);
const char * oaclient_credential_get_session(struct oaclient_credential *);

const char *oaclient_credential_get_scheme(struct oaclient_credential *self);
int oaclient_credential_set_scheme(struct oaclient_credential *self, const char *v);

const char *oaclient_credential_get_signing_method(struct oaclient_credential *self);
int oaclient_credential_set_signing_method(struct oaclient_credential *self, const char *v);

/*
 * oaclient_credential_set_expiry
 *
 * Updates the expiry, taking the number of seconds returned by the auth
 * server until the credential probably expires.
 */
int oaclient_credential_set_expiry(struct oaclient_credential *, unsigned int);
time_t oaclient_credential_get_expiry(struct oaclient_credential *);

/*
 * oaclient_cache
 *
 * Functions beginning with oaclient_cache control the underlying
 * credential cache.
 *
 * XXX Nothing analogous to kinit, because we don't know how to have a credential
 * without an explicit identity.
 */ 

/**
 * Enumerate the credentials currently in the database.  This is inteded for
 * implementing oalist (the oaclient equivalent to klist).
 *
 * The caller to this function does not need to oaclient_credential_destroy.
 */
int oaclient_cache_enumerate_credentials(struct oaclient_ctx *ctx,
                                         void (*one)(struct oaclient_credential *, void *rock),
                                         void *rock);

/** Forget a given credential. */
int oaclient_cache_forget_credential(struct oaclient_ctx *ctx, struct oaclient_credential *);

/** Forget any credential associated with an identity. */
int oaclient_cache_forget_credential_for_identity(struct oaclient_ctx *ctx, struct oaclient_identity *);

/**
 * Completely clear the cache.
 *
 * This can be used to implement oadestroy (ala kdestroy). 
 */
int oaclient_cache_clear(struct oaclient_ctx *ctx);

/*
 *
 * Does the caller have to oaclient_credential_destroy?  No.  How long is the
 * credential good for?  We should cache the "last" credential; if the caller
 * wants to keep the credential around longer, they can _clone it.
 */ 
int oaclient_get_credential(struct oaclient_credential **out,
                            struct oaclient_ctx *ctx,
                            struct oaclient_identity *sb);

/*
 * Get a cached credential -- don't go ask for one, just get locally.
 */ 
int oaclient_get_credential_from_cache(struct oaclient_credential **out,
                                       struct oaclient_ctx *ctx,
                                       struct oaclient_identity *sb);

/*
 * Get a cached credential if there is one for an endpoint.
 */ 
int oaclient_get_credential_for_endpoint(struct oaclient_credential **out,
					 struct oaclient_ctx *ctx,
					 struct oaclient_endpoint *ep);
/*
 * oaclient_cache_update
 * 
 * Update the cache for the current information set.  The identity 
 * must be set.  Endpoint or credential can be NULL, but not both.
 * This routine updates the endpoint/identity and identity credential
 * pairs together to insure integrity in case the cache has been flushed
 * and we don't know it.
 */ 
int oaclient_cache_update(struct oaclient_ctx *ctx,
			  struct oaclient_endpoint *ep,
			  struct oaclient_identity *id,
			  struct oaclient_credential *cred);

#ifdef __cplusplus
//}
#endif

#endif /* INCLUDED_OACLIENT_H */
