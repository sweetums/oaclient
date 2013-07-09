/* Oaclient library
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
#include <unistd.h>
#include "stdio.h"
#include "sql_db.h"
#include "sql_commands.h"
#include "oaclient.h"
#include "ctx.h"
#include "identity.h"
#include "credential.h"
#include "endpoint.h"


#define GET_NOT_NULL(type, source, varname) \
                     varname = type ## _get_ ## varname(source);\
                     if (!varname) varname = "" ;

/*
 * Open the db either on the provided argument path/filename or on the default.
 */
int oac_db_open(struct oaclient_ctx *ctx, const char *fn)
{
  const char *filename = fn;
  char *errmsg;
  int result;

  if (NULL == filename) 
    filename = SQL_DB_DEFAILT_FILENAME;

  if (OAC_OK != (result = oaclient_ctx_set_filename(ctx, filename)))
    return result;

  result = sqlite3_open(filename, &(ctx->db));
  if (SQLITE_OK != result)
    return OAC_FAIL;

  /* XXXXXXX Now we shoudl check that the DB is what we expect.  How to do this? */

  result = sqlite3_exec(ctx->db, SQL_DB_SCHEMA, NULL, NULL, &errmsg);
  if (SQLITE_OK != result) return OAC_FAIL;

  return OAC_OK;
}

void oac_db_close(struct oaclient_ctx *ctx)
{
  sqlite3_close(ctx->db);
  ctx->db = NULL;
}

/** Forget a given credential. */
int oaclient_cache_forget_credential(struct oaclient_ctx *ctx, 
				     struct oaclient_credential *cred)
{
  int result=OAC_FAIL;
  const char *scheme, *user, *realm, *scope;
  int sqlresult;

  if (!ctx || !oaclient_ctx_get_db(ctx) || !cred)
    return OAC_OK;

  sqlite3 *db = oaclient_ctx_get_db(ctx);
  sqlite3_stmt *stmt;
  const char *tail;
  struct oaclient_identity *id = oaclient_credential_get_identity(cred);

  char *statement1 = "DELETE FROM creds WHERE (scheme == :1 AND "
    "  identity == (SELECT ROWID FROM identities "
    "                 WHERE username == :2 AND realm == :3 AND hostname == :4 "
    "                 LIMIT 1));";

  GET_NOT_NULL(oaclient_credential, cred, scheme);
  GET_NOT_NULL(oaclient_identity, id, user);
  GET_NOT_NULL(oaclient_identity, id, realm);
  GET_NOT_NULL(oaclient_identity, id, scope);

  if (id && scheme && *scheme) {
    sqlresult = sqlite3_prepare(db, statement1, -1, &stmt, &tail);
    if (SQLITE_OK == sqlresult) {
      sqlite3_bind_text(stmt, 1, scheme, -1, NULL);
      sqlite3_bind_text(stmt, 2, user, -1, NULL);
      sqlite3_bind_text(stmt, 3, realm, -1, NULL);
      sqlite3_bind_text(stmt, 4, scope, -1, NULL);
      sqlresult = sqlite3_step(stmt);
      
      switch (sqlresult) {
      case SQLITE_DONE:
	result = OAC_OK;
	break;
      default:
	result = OAC_FAIL;
	break;
      }
      /* cleanup */
      sqlite3_finalize(stmt);
    }
  }

  return result;
}
/*
 * oaclient_cache_clear
 *
 * Clear the DB.  
 *
 * XXXXXXX We should probably be more destructive, writing into the
 * DB to overwrite the stuff in the file, or doing something like
 * writing random data to the file to scramble it.
 */
int oaclient_cache_clear(struct oaclient_ctx *ctx)
{
  char *errmsg;

  if (!ctx || !(oaclient_ctx_get_db(ctx)))
    return OAC_OK;
  sqlite3_exec(oaclient_ctx_get_db(ctx), SQL_DB_CLEAR, NULL, NULL, &errmsg);
  sqlite3_close(oaclient_ctx_get_db(ctx));
  if (ctx->db_filename)
    unlink(ctx->db_filename);

  return oac_db_open(ctx, ctx->db_filename);
}
/*
 * Worker functiosns for updating
 */

int oac_db_update_id(struct oaclient_ctx *ctx,
			  struct oaclient_identity *id)
{
  int result=OAC_FAIL;
  const char *user, *realm, *scope, *initiate_url, *authorization_url, *refresh_url;
  int sqlresult;

  sqlite3 *db = oaclient_ctx_get_db(ctx);
  sqlite3_stmt *stmt;
  const char *tail;

  char *statement1 = "INSERT OR REPLACE INTO identities "
    "  VALUES (:1, :2, :3, :4, :5, :6);";

  char *statement2 = "SELECT rowid FROM identities "
    "  WHERE (username==:1 AND realm==:2 AND scope==:3) LIMIT 1;";

  if (!id || !ctx)
    return OAC_BAD_PARAM;

  GET_NOT_NULL(oaclient_identity, id, user);
  GET_NOT_NULL(oaclient_identity, id, realm);
  GET_NOT_NULL(oaclient_identity, id, scope);
  GET_NOT_NULL(oaclient_identity, id, initiate_url);
  GET_NOT_NULL(oaclient_identity, id, authorization_url);
  GET_NOT_NULL(oaclient_identity, id, refresh_url);

  /* OK, do the insert */
  sqlresult = sqlite3_prepare(db, statement1, -1, &stmt, &tail);

  if (SQLITE_OK == sqlresult) {

    sqlite3_bind_text(stmt, 1, user, -1, NULL);
    sqlite3_bind_text(stmt, 2, realm, -1, NULL);
    sqlite3_bind_text(stmt, 3, scope, -1, NULL);
    sqlite3_bind_text(stmt, 4, initiate_url, -1, NULL);
    sqlite3_bind_text(stmt, 5, authorization_url, -1, NULL);
    sqlite3_bind_text(stmt, 6, refresh_url, -1, NULL);

    sqlresult = sqlite3_step(stmt);

    switch (sqlresult) {
    case SQLITE_DONE:
      result = OAC_OK;
      break;    
    default:
      result = OAC_FAIL;
      break;
    }
    /* cleanup */
    sqlite3_finalize(stmt);
  }

  if (OAC_OK != result)
    return result;

  /* Now get the rowid */
  sqlresult = sqlite3_prepare(db, statement2, -1, &stmt, &tail);

  if (SQLITE_OK == sqlresult) {

    sqlite3_bind_text(stmt, 1, user, -1, NULL);
    sqlite3_bind_text(stmt, 2, realm, -1, NULL);
    sqlite3_bind_text(stmt, 3, scope, -1, NULL);

    sqlresult = sqlite3_step(stmt);

    switch (sqlresult) {
    case SQLITE_ROW:
      oaclient_identity_set_rowid(id, sqlite3_column_int(stmt, 0));
      result = OAC_OK;
      break;    
    default:
      result = OAC_FAIL;
      break;
    }
    /* cleanup */
    sqlite3_finalize(stmt);
  }

  return result;
}
int oac_db_update_ep(struct oaclient_ctx *ctx,
		     struct oaclient_identity *id, 
		     struct oaclient_endpoint *ep)
{
  int result=OAC_FAIL;
  const char *realm, *username, *hostname, *path;
  int sqlresult;

  sqlite3 *db = oaclient_ctx_get_db(ctx);
  sqlite3_stmt *stmt;
  const char *tail;

  char *statement = "REPLACE INTO endpoints VALUES (:1, :2, :3, :4, :5, :6);";

  //    "SELECT ROWID FROM endpoints WHERE username = :2 AND hostname = :3 AND port = :4;";

  if (!ctx || !id || !ep)
    return OAC_BAD_PARAM;

  GET_NOT_NULL(oaclient_identity, id, realm);
  GET_NOT_NULL(oaclient_endpoint, ep, username);
  GET_NOT_NULL(oaclient_endpoint, ep, hostname);
  GET_NOT_NULL(oaclient_endpoint, ep, path);


  /* OK, do the deal */
  sqlresult = sqlite3_prepare(db, statement, -1, &stmt, &tail);

  if (SQLITE_OK == sqlresult) {

    sqlite3_bind_text(stmt, 1, realm, -1, NULL);
    sqlite3_bind_text(stmt, 2, username, -1, NULL);
    sqlite3_bind_text(stmt, 3, hostname, -1, NULL);
    sqlite3_bind_int(stmt, 4, oaclient_endpoint_get_port(ep));
    sqlite3_bind_text(stmt, 5, path, -1, NULL);
    sqlite3_bind_int(stmt, 6, oaclient_identity_get_rowid(id));

    sqlresult = sqlite3_step(stmt);

    switch (sqlresult) {
    case SQLITE_DONE:
      //      oaclient_endpoint_set_rowid(ep, sqlite3_column_int(stmt, 0));
      result = OAC_OK;
      break;    
    default:
      result = OAC_FAIL;
      break;
    }
    /* cleanup */
    sqlite3_finalize(stmt);
  }

  return result;
}
int oac_db_update_cred(struct oaclient_ctx *ctx,
		       struct oaclient_identity *id,
		       struct oaclient_credential *cred)
{
  int result=OAC_FAIL;
  const char *scheme, *token, *secret, *session;
  int sqlresult;

  sqlite3 *db = oaclient_ctx_get_db(ctx);
  sqlite3_stmt *stmt;
  const char *tail;

  char *statement = "REPLACE INTO creds VALUES (:1, :2, :3, :4, :5, :6);";
  //  char *statement2 = "SELECT ROWID FROM creds WHERE identity = :1 AND scheme = :2;";

  if (!ctx || !id || !cred)
    return OAC_BAD_PARAM;

  GET_NOT_NULL(oaclient_credential, cred, scheme);
  GET_NOT_NULL(oaclient_credential, cred, token);
  GET_NOT_NULL(oaclient_credential, cred, secret);
  GET_NOT_NULL(oaclient_credential, cred, session);


  /* OK, do the deal */
  sqlresult = sqlite3_prepare(db, statement, -1, &stmt, &tail);

  if (SQLITE_OK == sqlresult) {

    sqlite3_bind_int(stmt, 1, oaclient_identity_get_rowid(id));
    sqlite3_bind_text(stmt, 2, scheme, -1, NULL);
    sqlite3_bind_text(stmt, 3, token, -1, NULL);
    sqlite3_bind_text(stmt, 4, secret, -1, NULL);
    sqlite3_bind_text(stmt, 5, session, -1, NULL);
    sqlite3_bind_int(stmt, 6, oaclient_credential_get_expiry(cred));

    sqlresult = sqlite3_step(stmt);

    switch (sqlresult) {
    case SQLITE_DONE:
      //      oaclient_credential_set_rowid(cred, sqlite3_column_int(stmt, 0));
      result = OAC_OK;
      break;
    default:
      result = OAC_FAIL;
      break;
    }
    /* cleanup */
    sqlite3_finalize(stmt);
  }

  return result;
}

#undef GET_NOT_NULL

/*
 * oaclient_cache_update
 * 
 * Update the cache for the current information set.  The identity 
 * must be set.  Endpoint or credential can be NULL, but not both.
 * This routine updates the endpoint/identity and identity credential
 * pairs together to insure integrity in case the cache has been flushed
 * and we don't know it.
 *
 * This will update the structures with the appropriate ROWIDs (which 
 * might be useless, but I think we might want it).
 */ 
int oaclient_cache_update(struct oaclient_ctx *ctx,
			  struct oaclient_endpoint *ep,
			  struct oaclient_identity *id,
			  struct oaclient_credential *cred)
{
  int result=OAC_FAIL;
  int sqlresult;

  sqlite3 *db = oaclient_ctx_get_db(ctx);
  sqlite3_stmt *stmt;
  const char *tail;

  if (!id || (!ep && !cred))
    return OAC_BAD_PARAM;

  /* Begin our transaction */
  sqlresult = sqlite3_prepare(db, "BEGIN;", -1, &stmt, &tail);
  sqlresult = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  result = oac_db_update_id(ctx, id);
  if (cred && (OAC_OK == result)) {
    result = oac_db_update_cred(ctx, id, cred);
  }
  if (ep && (OAC_OK == result)) {
    result = oac_db_update_ep(ctx, id, ep);
  }

  /* Finalize everything */
  if (OAC_OK == result) {
    sqlresult = sqlite3_prepare(db, "COMMIT;", -1, &stmt, &tail);
  } else {
    sqlresult = sqlite3_prepare(db, "ABORT;", -1, &stmt, &tail);
  }
  sqlresult = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  return result;
}


