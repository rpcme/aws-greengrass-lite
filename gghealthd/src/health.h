/* gravel - Utilities for AWS IoT Core clients
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates
 */

#ifndef GGHEALTHD_HEALTH_H
#define GGHEALTHD_HEALTH_H

#include "gravel/object.h"

/* get status from native orchestrator or local database */
GravelObject gghealthd_get_status(GravelBuffer componentName);

/* update status (with GG component lifecycle state) in native orchestrator or
 * local database */
int ggheatlhd_update_status(GravelBuffer componentName, GravelBuffer status);

#endif
