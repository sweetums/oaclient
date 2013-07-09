/*
 * Copyright (c) 2013, Yahoo! Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * See accompanying LICENSE file for terms.
 */
#ifndef INCLUDED_ACCESSOR_H
#define INCLUDED_ACCESSOR_H

#include <errno.h>

/* internal-use header file */

/* This macro provides a convenient way of implementing trivial accessor
 * functions.
 */
#define DEFINE_GETTER(return_type, type, field)        \
    return_type type ## _get_ ## field(struct type *self) {     \
        if (!self) return 0;                                 \
        return self->field;                                     \
    }

/*
 * This function defines a setter.  "duplicate" is an expression that copies
 * the value as needed.  The passed-in value always has the name "v".  For
 * scalars, "v" is sufficient; for const char *, "strdup(v)" is the right thing
 * for now.
 */ 
#define DEFINE_SETTER(data_type, type, field, duplicate)                \
    int type ## _set_ ## field(struct type *self, data_type v) {        \
      if (!self) return OAC_FAIL;                                       \
      if (self->field) free(self->field);				\
      if (NULL == v) {self->field = NULL; return 0;} 		        \
      self->field = strdup(v);					\
      if (!self->field) return ENOMEM;                                  \
      return 0;                                                         \
    }

#define DEFINE_INT_SETTER(data_type, type, field, duplicate)            \
  int type ## _set_ ## field(struct type *self, data_type v) {		\
       self->field = v;                                               \
       return 0;			       \
  }

#endif
