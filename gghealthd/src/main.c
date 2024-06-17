/* gravel - Utilities for AWS IoT Core clients
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates
 */

#include "args.h"
#include "gravel/log.h"
#include "gravel/object.h"
#include "gravel/server.h"
#include "gravel/utils.h"
#include "health.h"
#include <argp.h>
#include <string.h>
#include <stdlib.h>

static char doc[] = "gghealthd -- Component Health Status Update and Querying";

static struct argp_option opts[] = { { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    (void) arg;
    (void) state;
    switch (key) {
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { opts, arg_parser, 0, doc, 0, 0, 0 };

int main(int argc, char **argv) {
    GghealthdArgs args = { 0 };

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &args);

    gravel_listen(GRAVEL_STR("/aws/gravel/gghealthd"), NULL);
}
