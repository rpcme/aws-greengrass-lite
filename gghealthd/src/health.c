
#include "health.h"
#include "gravel/buffer.h"
#include "gravel/log.h"
#include "gravel/map.h"
#include "gravel/object.h"
#include <assert.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <stdlib.h>

// destinations
#define DEFAULT_DESTINATION "org.freedesktop.systemd1"

// paths
#define DEFAULT_PATH "/org/freedesktop/systemd1"

// interfaces
#define MANAGER_INTERFACE "org.freedesktop.systemd1.Manager"
#define SERVICE_INTERFACE " org.freedesktop.systemd1.Service"
#define UNIT_INTERFACE "org.freedesktop.systemd1.Unit"

// needed to free heap-allocated strings returned by sd-bus
__attribute__((nonnull, always_inline)) static inline void
free_string(char **str) {
    free(*str);
}

static sd_bus *open_bus(void) {
    sd_bus *bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0) {
        GRAVEL_LOGE(
            "gghealthd", "Unable to open default system bus (errno=%d)", -ret
        );
        return NULL;
    }
    return bus;
}

// N.D: returned message must be unref'd by caller
static sd_bus_message *get_unit_path(sd_bus *bus, GravelBuffer componentName) {
    sd_bus_message *reply = NULL;
    __attribute__((cleanup(sd_bus_error_free))) sd_bus_error error
        = SD_BUS_ERROR_NULL;
    int ret = 0;

    ret = sd_bus_call_method(
        bus,
        DEFAULT_DESTINATION,
        DEFAULT_PATH,
        MANAGER_INTERFACE,
        "GetUnit",
        &error,
        &reply,
        "s",
        (const char *) componentName.data
    );

    if (ret < 0) {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to load Component %.*s (errno=%d) (name=%s) (message=%s)",
            (int) componentName.len,
            componentName.data,
            -ret,
            error.name,
            error.message
        );
        return NULL;
    }

    return reply;
}

// N.D: returned string must be freed by caller
static char *get_property_string(
    sd_bus *bus, GravelBuffer componentName, char *interface, char *property
) {
    __attribute__((cleanup(sd_bus_message_unrefp))) sd_bus_message *reply
        = get_unit_path(bus, componentName);
    if (reply == NULL) {
        return NULL;
    }
    const char *unitPath = NULL;
    int ret = 0;
    ret = sd_bus_message_read_basic(reply, 'o', &unitPath);

    if (ret < 0) {
        return NULL;
    }

    char *value = NULL;
    __attribute__((cleanup(sd_bus_error_free))) sd_bus_error error
        = SD_BUS_ERROR_NULL;
    ret = sd_bus_get_property_string(
        bus, DEFAULT_DESTINATION, unitPath, interface, property, &error, &value
    );
    if (ret < 0) {
        return NULL;
    }
    return value;
}

static int get_pid(sd_bus *bus, GravelBuffer componentName) {
    // TODO: there are MAIN_PID and CONTROL_PID properties. MAIN_PID is probably
    // sufficient for sd_pid_notify. Components probably won't have more than
    // one active processes.
    __attribute__((cleanup(free_string))) char *pidStr = get_property_string(
        bus, componentName, SERVICE_INTERFACE, "MAIN_PID"
    );
    if (pidStr == NULL) {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to get PID for component %.*s",
            (int) componentName.len,
            componentName.data
        );
        return -1;
    }
    int pid = atoi(pidStr);
    free(pidStr);
    return pid;
}

GravelObject gghealthd_get_status(GravelBuffer componentName) {
    __attribute__((cleanup(sd_bus_unrefp))) sd_bus *bus = open_bus();
    if (bus == NULL) {
        return GRAVEL_OBJ_I64(ENOSYS);
    }
    __attribute__((cleanup(sd_bus_message_unrefp))) sd_bus_message *reply
        = get_unit_path(bus, componentName);

    if (reply == NULL) {
        // TODO: If we get here, then we have to check the component store for
        // NEW or INSTALLED components
        return GRAVEL_OBJ_I64(ENOENT);
    }

    const char *unitPath = NULL;
    int ret = sd_bus_message_read_basic(reply, 'o', &unitPath);

    if (ret < 0) {
        return GRAVEL_OBJ_I64(EPROTO);
    }

    __attribute__((cleanup(free_string))) char *type = NULL;
    __attribute__((cleanup(sd_bus_error_free))) sd_bus_error error
        = SD_BUS_ERROR_NULL;
    ret = sd_bus_get_property_string(
        bus,
        DEFAULT_DESTINATION,
        unitPath,
        UNIT_INTERFACE,
        "ActiveState",
        &error,
        &type
    );

    if (ret < 0) {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to retrieve Component status %.*s (path=%s) (errno=%d) "
            "(name=%s) (message=%s)",
            (int) componentName.len,
            (const char *) componentName.data,
            unitPath,
            -ret,
            error.name,
            error.message
        );
        return GRAVEL_OBJ_I64(EPROTO);
    }

    const GravelMap statusMap = GRAVEL_MAP(
        { GRAVEL_STR("activating"), GRAVEL_OBJ_STR("STARTING") },
        { GRAVEL_STR("active"), GRAVEL_OBJ_STR("RUNNING") },
        // `reloading` doesn't have any mapping to greengrass. It's an active
        // component whose systemd (not greengrass) configuration is reloading
        { GRAVEL_STR("reloading"), GRAVEL_OBJ_STR("RUNNING") },
        { GRAVEL_STR("deactivating"), GRAVEL_OBJ_STR("STOPPING") },
        // inactive and failed are ambiguous
        { GRAVEL_STR("inactive"), GRAVEL_OBJ_NULL() },
        { GRAVEL_STR("failed"), GRAVEL_OBJ_NULL() },
    );

    const GravelBuffer key = { .data = (uint8_t *) type, .len = strlen(type) };
    GravelObject *value = NULL;
    if (!gravel_map_get(statusMap, key, &value)) {
        // unreachable?
        GRAVEL_LOGE(
            "gghealthd",
            "unknown systemd ActiveState %.*s",
            (int) key.len,
            key.data
        );
        return GRAVEL_OBJ_I64(EPROTO);
    }
    if (value->type == GRAVEL_TYPE_BUF) {
        return *value;
    }

    // disambiguate `failed` and `inactive`
    uint64_t timestamp = 0;
    ret = sd_bus_get_property_trivial(
        bus,
        DEFAULT_DESTINATION,
        unitPath,
        UNIT_INTERFACE,
        "InactiveEnterTimestampMonotonic",
        &error,
        't',
        &timestamp
    );
    if (ret < 0) {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to retrieve Component last run timestamp %.*s (path=%s) "
            "(errno=%d) (name=%s) (message=%s)",
            (int) componentName.len,
            (const char *) componentName.data,
            unitPath,
            -ret,
            error.name,
            error.message
        );
        return GRAVEL_OBJ_I64(EPROTO);
    }
    if (timestamp == 0) {
        return GRAVEL_OBJ_STR("INSTALLED");
    }
    __attribute__((cleanup(free_string))) char *result = NULL;
    ret = sd_bus_get_property_string(
        bus,
        DEFAULT_DESTINATION,
        unitPath,
        UNIT_INTERFACE,
        "Result",
        &error,
        &result
    );
    if (ret < 0) {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to retrieve Component Result property %.*s (path=%s) "
            "(errno=%d) (name=%s) (message=%s)",
            (int) componentName.len,
            (const char *) componentName.data,
            unitPath,
            -ret,
            error.name,
            error.message
        );
        return GRAVEL_OBJ_I64(EPROTO);
    }

    GravelBuffer resultBuf
        = { .data = (uint8_t *) result, .len = strlen(result) };
    if (gravel_buffer_eq(resultBuf, GRAVEL_STR("success"))) {
        return GRAVEL_OBJ_STR("FINISHED");
    } else if (gravel_buffer_eq(resultBuf, GRAVEL_STR("start-limit"))) {
        return GRAVEL_OBJ_STR("BROKEN");
    } else {
        return GRAVEL_OBJ_STR("ERRORED");
    }
}

int ggheatlhd_update_status(GravelBuffer componentName, GravelBuffer status) {
    __attribute__((cleanup(sd_bus_unrefp))) sd_bus *bus = open_bus();
    if (bus == NULL) {
        return ENOSYS;
    }

    const GravelMap statusMap = GRAVEL_MAP(
        { GRAVEL_STR("RUNNING"), GRAVEL_OBJ_STR("READY=1") },
        { GRAVEL_STR("ERRORED"), GRAVEL_OBJ_STR("ERRNO=71") }
    );

    GravelObject *obj = NULL;
    if (!gravel_map_get(statusMap, status, &obj)) {
        GRAVEL_LOGE(
            "gghealthd",
            "Invalid status update \"%.*s\" for component %.*s",
            (int) status.len,
            status.data,
            (int) componentName.len,
            componentName.data
        );
        return EINVAL;
    }

    int pid = get_pid(bus, componentName);
    if (pid <= 0) {
        return ENOENT;
    }

    int ret = sd_pid_notify(pid, 0, (const char *) obj->buf.data);
    if (ret == 0) {
        GRAVEL_LOGI(
            "gghealthd",
            "Component %.*s reported state updating to %.*s\n",
            (int) componentName.len,
            componentName.data,
            (int) status.len,
            status.data
        );
    } else {
        GRAVEL_LOGE(
            "gghealthd",
            "Unable to update component state for %.*s to %.*s (errno=%d)",
            (int) componentName.len,
            componentName.data,
            (int) status.len,
            status.data,
            -ret
        );
    }

    return -ret;
}
