# LCA-ARCH-28: Worker lifecycle, resource ownership, and failure containment

- Status: Accepted
- Decision: The experimental worker has a typed lifecycle, one job, and no retry of a denied request. Closing the job ends the worker. The active-process limit blocks a second process. None of this is installed on the production agent.
- Milestone: LCA-01M

## Lifecycle

`Lifecycle::step` accepts only the edges below. `Failed` has no edge to `Starting`.

| From | To |
| --- | --- |
| Created | Starting, Terminated |
| Starting | Ready, Failed, Terminated |
| Ready | Running, Stopping, Failed, Terminated |
| Running | Stopping, Failed, Terminated |
| Stopping | Stopped, Failed, Terminated |
| Stopped | Terminated |
| Failed | Terminated |

A launch that reaches user code is walked `Created → Starting → Ready → Running → Stopping → Stopped → Terminated`, and a further `Starting` is rejected. A launch that does not reach user code goes `Starting → Failed → Terminated`. The unit test covers the failed path. The access experiment asserts the successful trace ends at `Terminated`.

The state machine records the harness. It does not by itself kill a process. The job does that.

## Job and limits

`CreateJobObjectW` then `SetInformationJobObject`. The worker is assigned while suspended, then resumed.

| Limit | API result in this run |
| --- | --- |
| `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | included; `limits=0` |
| Active process count `1` | included |
| Die on unhandled exception | included |
| Per-process user time, 30 seconds | included (`time=1`) |
| Process memory, 1 GiB | accepted (`memory=1`) |
| CPU rate hard cap, 50% | accepted (`cpu=0`) |

`limits=0 memory=1 time=1 cpu=0` means those `SetInformationJobObject` calls returned success. No network, clipboard, or window-station limit was set. IPC size (1024 bytes) and the rate cap are broker checks, not job limits.

## Failure containment that was run

| Case | Measured |
| --- | --- |
| Worker blocked on the request pipe, then the only job handle is dropped | `in_job=1`. Exit `0x0`, not `259` (`STILL_ACTIVE`). The report contained `reached=1` and did not contain `wait_returned=1`. |
| Worker calls `CreateProcessW` on `cmd.exe /c exit` | API failed with `1816` (`ERROR_NOT_ENOUGH_QUOTA`). The test treats any non-zero code as the child not starting. |
| Invalid capability, replay, foreign resource, stale timestamp, ninth message, oversize frame, parent pid using the worker id | Denied. Audit lines match the decisions. No second attempt is issued. |
| Secrets after each run | Byte-identical to the snapshot taken before launch. |

Exit `0x0` on the kill run is the code observed after the job handle was closed. It is not `STILL_ACTIVE`. The wait script writes `wait_returned=1` only after `ReadFile` returns, and that line was absent, so the wait did not finish. There is no automatic retry of a mutating operation: the broker has no write capability, and a deny ends that request.

Handle lifetime follows the child and the job. Dropping the child terminates a still-running process and closes the process, thread, pipe, and any private desktop handles. The passing launch did not open a private desktop.

## What is not claimed

- That a job replaces a different security principal.
- That `1816` was confirmed by reading the kernel's job counter. The API returned that code under an active-process limit of 1, and the test required a non-zero code.
- That orphaned processes outside the job were hunted beyond this worker. The spawn attempt did not create a child.
- That production code assigns the agent to a job.
