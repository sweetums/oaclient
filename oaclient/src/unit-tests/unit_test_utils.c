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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int print_result(char *name, char *test, int expected, int result)
{
  if ((expected && result) || (!expected && !result)) {
    printf("%s: %s \t\tPASSED\n", name, test);
    return 0;
  } else {
    printf("%s: %s \t\tFAILED\n", name, test);
    return 1;
  }
}

