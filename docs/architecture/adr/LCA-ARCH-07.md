# LCA-ARCH-07: Bounded multi-turn agent loop

- Status: Accepted
- Decision: A separate controller with explicit states and separate budgets
- Milestone: LCA-01F

## Context

LCA-01E stops after one generation. Tool results are printed and are not sent back. A coding task that needs a search and then a read cannot finish in that shape.

An unbounded loop would let the model raise its own budget, recover from a tool error with another generation, or continue after a patch that still needs a human grant. `limits.max_steps` is already the single-turn action cap. Reusing it as a turn count would raise the turn budget whenever an old config set a large action cap.

## Decision

Add `BoundedAgentController` beside `SingleTurnAgentController`. `lca agent run` keeps the single-turn controller. `lca agent execute` uses the bounded controller.

The loop is a state machine. Terminal states are `Completed`, `Failed`, and `BudgetExhausted`. They have no outgoing edge. Every other state may enter `Failed` or `BudgetExhausted`. The forward edges are:

```text
Initialized -> ModelRequested -> ModelResponded
ModelResponded -> Completed                 final answer
ModelResponded -> ValidatingActions
ValidatingActions -> ExecutingTools
ExecutingTools -> Completed                 prepared patch
ExecutingTools -> PreparingNextTurn
PreparingNextTurn -> ModelRequested
```

A model turn is reserved in `ModelRequested` before `generate`. A transport error, a protocol error, a rejected batch, a tool error, a policy denial, a prepared patch, a cancel, and a spent budget do not reserve another turn.

Budgets are separate and are fixed before the first generation:

| Budget | Default | Cap |
| --- | ---: | ---: |
| Model turns | 5 | 1 through 32 |
| Actions per turn | 8 | 1 through 8 |
| Actions per run | 20 | 1 through 64 |
| Tool-result bytes | 512 KiB | 1 through 8 MiB |
| Conversation history | 1 MiB | 1 through 8 MiB |
| Run timeout | 180 seconds | 1 ms through 24 h in the controller; whole seconds in `[agent]` |

`limits.max_steps` stays the single-turn action cap. It is not read as a turn budget. `limits.timeout_secs` stays the LCA-01A timeout. The execute run uses `[agent].timeout_secs`.

The model cannot change these numbers. A budget object in the next request is data the controller computed. The next request is still checked in Rust.

## Consequences

- `lca-core` still does not open sockets and does not perform filesystem work itself. It calls `ModelRuntime` and `dispatch_validated`.
- A spent turn budget returns `budget_exhausted` and `turn_budget`. The controller does not invent a final answer.
- `apply_patch` stays prepare-only. A prepared patch completes the run. A later model turn cannot apply it. The approval binding remains process-local, so `agent execute` does not print a confirmation line.
- A tool error keeps earlier actions from that batch, skips the rest, and stops. There is no model recovery turn.
- Conversation history is capped. Tool results are untrusted user or tool messages. They are not system instructions.

## Alternatives not taken

- Extending `SingleTurnAgentController` until `run` loops.
- One shared `max_steps` for turns and actions.
- Continuing after a prepared patch so the model can say `approve`.
- Automatic JSON-to-native retry inside the loop.
- Shell, process, or network tools.
