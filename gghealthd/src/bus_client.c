// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "bus_client.h"
#include <ggl/alloc.h>
#include <ggl/bump_alloc.h>
#include <ggl/core_bus/client.h>
#include <ggl/defer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <pthread.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#define KEY_PREFIX "component/"
#define KEY_SUFFIX "/version"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1U)
#define KEY_SUFFIX_LEN (sizeof(KEY_SUFFIX) - 1U)

static pthread_mutex_t bump_alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t bump_buffer[4096];

// Check a component's version field in ggconfigd for proof of existence
GglError verify_component_exists(GglBuffer component_name) {
    int ret = pthread_mutex_lock(&bump_alloc_mutex);
    if (ret < 0) {
        return GGL_ERR_FAILURE;
    }
    GGL_DEFER(pthread_mutex_unlock, bump_alloc_mutex);
    GglBumpAlloc alloc = ggl_bump_alloc_init(GGL_BUF(bump_buffer));

    const size_t capacity
        = component_name.len + KEY_PREFIX_LEN + KEY_SUFFIX_LEN;
    GglByteVec key
        = { .buf = (GglBuffer
            ) { .data = GGL_ALLOCN(&alloc.alloc, uint8_t, capacity), .len = 0 },
            .capacity = capacity };
    if (key.buf.data == NULL) {
        return GGL_ERR_NOMEM;
    }
    ggl_byte_vec_append(&key, GGL_STR(KEY_PREFIX));
    ggl_byte_vec_append(&key, component_name);
    ggl_byte_vec_append(&key, GGL_STR(KEY_SUFFIX));

    GglBuffer server = GGL_STR("/aws/ggl/ggconfigd");
    GglMap params = GGL_MAP(
        { GGL_STR("component"), GGL_OBJ_STR("gghealthd") },
        { GGL_STR("key"), GGL_OBJ(key.buf) },
    );
    GglObject result;
    GglError method_error = GGL_ERR_OK;
    GglError error = ggl_call(
        server, GGL_STR("read"), params, &method_error, &alloc.alloc, &result
    );
    if (error != GGL_ERR_OK) {
        GGL_LOGE("gghealthd", "failed to connect to ggconfigd");
        return error;
    }
    if (method_error != GGL_ERR_OK) {
        GGL_LOGE("gghealthd", "component does not exist in registry");
        return GGL_ERR_NOENTRY;
    }
    if (result.type == GGL_TYPE_BUF) {
        GGL_LOGT(
            "gghealthd",
            "read %.*s",
            (int) result.buf.len,
            (const char *) result.buf.data
        );
    }
    return GGL_ERR_OK;
}
