/* gravel - Utilities for AWS IoT Core clients
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates
 */

#include "gravel/buffer.h"
#include "gravel/log.h"
#include "gravel/map.h"
#include "gravel/object.h"
#include "gravel/server.h"
#include "health.h"
#include <errno.h>
#include <stdint.h>

static void
get_status(GravelBuffer componentName, GravelResponseHandle *handle) {
    GravelObject status = gghealthd_get_status(componentName);
    if (status.type == GRAVEL_TYPE_BUF) {
        GRAVEL_LOGD(
            "gghealthd",
            "%.*s is %.*s",
            (int) componentName.len,
            componentName.data,
            (int) status.buf.len,
            status.buf.data
        );
        gravel_respond(handle, 0, status);
    } else if (status.type == GRAVEL_TYPE_I64) {
        gravel_respond(handle, (int) status.i64, GRAVEL_OBJ_NULL());
    }
    __builtin_unreachable();
}

static void update_status(
    GravelBuffer componentName,
    GravelBuffer componentStatus,
    GravelResponseHandle *handle
) {
    int ret = ggheatlhd_update_status(componentName, componentStatus);
    gravel_respond(handle, ret, GRAVEL_OBJ_NULL());
}

void gravel_receive_callback(
    void *ctx,
    GravelBuffer method,
    GravelList params,
    GravelResponseHandle *handle
) {
    (void) ctx;

    if ((params.len < 1) || (params.items[0].type != GRAVEL_TYPE_BUF)) {
        GRAVEL_LOGE(
            "rpc-handler",
            "Received invalid arguments. Expected at least 1, got %zu. "
            "Expected type is %d (GRAVEL_TYPE_BUF), got %d",
            params.len,
            GRAVEL_TYPE_BUF,
            (params.len >= 1 ? params.items[0].type : GRAVEL_TYPE_NULL)
        );
        gravel_respond(handle, EINVAL, GRAVEL_OBJ_NULL());
        return;
    }

    GravelBuffer componentName = params.items[0].buf;

    if (gravel_buffer_eq(GRAVEL_STR("get-status"), method)) {
        get_status(componentName, handle);
        return;
    } else if (gravel_buffer_eq(GRAVEL_STR("update-status"), method)) {
        if ((params.len < 2) || (params.items[1].type != GRAVEL_TYPE_BUF)) {
            GRAVEL_LOGE(
                "rpc-handler",
                "Received invalid arguments. Expected at least 2, got %zu. "
                "Expected type for second argument is %d (GRAVEL_TYPE_BUF), "
                "got %d",
                params.len,
                GRAVEL_TYPE_BUF,
                (params.len >= 2 ? params.items[1].type : GRAVEL_TYPE_NULL)
            );
            gravel_respond(handle, EINVAL, GRAVEL_OBJ_NULL());
            return;
        } else {
            GravelBuffer componentStatus = params.items[1].buf;
            update_status(componentName, componentStatus, handle);
        }
    } else {
        GRAVEL_LOGE(
            "rpc-handler",
            "Unknown method \"%.*s\". Implemented RPCs are get-status and "
            "update-status",
            (int) method.len,
            method.data
        );
        gravel_respond(handle, ENOENT, GRAVEL_OBJ_NULL());
    }
}
