/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#ifndef INCLUDED_OACLIENT_CREDENTIAL_H
#define INCLUDED_OACLIENT_CREDENTIAL_H

// #include <sqlite3.h>

struct oaclient_credential {
    struct oaclient_identity *ident;
    char *scheme;               /* OAUTH (OAuth 1.0a), BEARER, .... */
    char *token;
    char *secret;
    char *session;
    char *session_secret;
    time_t expiry;              /* hint of when this will probably expire 
				 * This will be local time.  Expiry is sent
				 * from the server as seconds form now.
				 */
    char *signing_method;       /*  hmac-sha-1, hmac-sha-256,hmac-sha-1 .... */
    int failures;
    int rowid;
};

/*
 * DB interaction.
 */
int oaclient_credential_store(struct oaclient_credential *self);

int oaclient_credential_set_rowid(struct oaclient_credential *self, unsigned row);
int oaclient_credential_get_rowid(struct oaclient_credential *self);

#endif /* INCLUDED_OACLIENT_CREDENTIAL_H */

