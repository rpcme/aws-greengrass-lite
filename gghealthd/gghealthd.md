# GG-Lite gghealthd

`gghealthd` is a core component daemon which reports and updates the lifecycle
states of non-core components on the platform’s native orchestration system.
RPCs given to `gghealthd` are translated and forwarded to the underlying
orchestrator running Greengrass-Lite on the device.

## 1.1 get-status <componentName: UTF-8 Buffer>

Returns the current component lifecycle state of the given compone ent name as a
UTF-8 buffer. The allowed responses are given as the following:

- “NEW” - The component is part of an active deployment and has not finished
  installing or is not yet registered with the orchestrator.
- “INSTALLED“ - The component is ready to be started by the orchestrator.
- “STARTING” - The component’s start lifecycle step is executing.
- “RUNNING” - The component’s run lifecycle step is executing, or its start
  lifecycle step is executing has issued an IPC to signal readiness.

> Note: components have one of either a `run` lifecycle step or a `start`
> lifecycle step. Components with a `start` lifecycle step require additional
> integration with the underlying orchestrator (that is, forwarding the GGv2
> `UpdateState` IPC).

- “STOPPING” - The component’s stop lifecycle step is executing.
- “FINISHED” - The component has successfully completed its lifecycle and is no
  longer executing.
- “ERRORED” - The component failed to execute one of its lifecycle steps and is
  scheduled to retry.
- “BROKEN” - The component has failed to execute its lifecycle and cannot retry.

The response is given as a Buffer containing UTF-8 with one of these unquoted
states on success. Otherwise, the response is given as a Null object and an
errno on failure.

- EINVAL - Argument validation error (client error)
- ESRCH - Component does not exist in the config (client error)
- EBUSY - Error connecting to orchestrator (server error, transient)

> Note: Implementations should prefer to use a very small exponential backoff
> (i.e. waiting on the order of microseconds, ramping up to a second) over
> spuriously failing to connect to the orchestrator. In practice, `gghealthd` is
> run by the orchestrator; therefore, it should always be able to succeed in
> connecting.

- EPROTO - Error forwarding request to orchestrator (server error)

If the component exists in the config but not in the underlying orchestrator,
`gghealthd` must respond with “NEW”.

## 1.2 get-status

If given no arguments, then `gghealthd` must take a snapshot of all configured
components into a single response, mapping its component name (UTF-8) to its
current lifecycle state (UTF-8).

```c
GravelMap stateMap = GRAVEL_MAP(
    { componentName1, lifecycleState1 },
    { componentName2, lifecycleState2 },
    { ..., ... },
    { componentNameN, lifecycleStateN }
);
gravel_respond(handle, 0, response);
```

This overload will be used to report overall device health and/or the current
deployment status. This overload may return a Null object and respond with the
following errno:

- EBUSY - Error connecting to orchestrator (server error, transient)

## 2 update-status <componentName: UTF-8 Buffer> <lifecycleState: UTF-8 Buffer>

Updates the component to the new lifecycle state (see above). This update is
translated and forwarded to underlying orchestrator running Greengrass-Lite. The
response is always a Null object, with an optional errno specifying a failure.

- EINVAL - Argument validation error (client error)
- ESRCH - Component does not exist in the config (client error)
- EBUSY - Error connecting to orchestrator (server error, transient)
- EPROTO - Error forwarding request to orchestrator (server error)

If the underlying orchestrator does not support custom state management, then
the request must be acknowledged with no action taken. For example, in `systemd`
this request will only be acknowledged if a component has custom state
transitioning (i.e. has a startup script and uses Greengrass IPC to send state
updates), but only for `RUNNING`, `STOPPING`, and `ERRORED`.

> Note: in GreengrassV2, the only supported state changes via the `UpdateState`
> IPC service are `RUNNING` and `ERRORED`, and they are only acknowledged if
> received during a Start lifecycle step. So, in practice, `STOPPING` is not
> required to be supported.

This definition allows a ComponentRunner which notifies about each state
transition for coordinating platform-agnostic orchestration, with valid
component state updates becoming either a component database update or forwarded
to an orchestrator as appropriate.
