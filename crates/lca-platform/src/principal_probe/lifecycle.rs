//! Typed worker lifecycle. Illegal edges fail. `Failed` has no path back to `Starting`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Created,
    Starting,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed,
    Terminated,
}

pub(super) struct Lifecycle {
    phase: Phase,
}

impl Lifecycle {
    pub(super) const fn new() -> Self {
        Self {
            phase: Phase::Created,
        }
    }

    pub(super) const fn phase(&self) -> Phase {
        self.phase
    }

    pub(super) fn step(&mut self, next: Phase) -> Result<Phase, Phase> {
        if legal(self.phase, next) {
            self.phase = next;
            Ok(next)
        } else {
            Err(self.phase)
        }
    }
}

fn legal(from: Phase, to: Phase) -> bool {
    use Phase::{Created, Failed, Ready, Running, Starting, Stopped, Stopping, Terminated};
    matches!(
        (from, to),
        (Created, Starting)
            | (Created, Terminated)
            | (Starting, Ready)
            | (Starting, Failed)
            | (Starting, Terminated)
            | (Ready, Running)
            | (Ready, Stopping)
            | (Ready, Failed)
            | (Ready, Terminated)
            | (Running, Stopping)
            | (Running, Failed)
            | (Running, Terminated)
            | (Stopping, Stopped)
            | (Stopping, Failed)
            | (Stopping, Terminated)
            | (Failed, Terminated)
            | (Stopped, Terminated)
    )
}

/// Walks a launch to `Terminated` and then rejects another start.
pub(super) fn trace_for_launch(reached: bool) -> Result<Vec<Phase>, Phase> {
    let mut life = Lifecycle::new();
    let mut trace = vec![life.phase()];
    let mut path = vec![Phase::Starting];
    if reached {
        path.extend([
            Phase::Ready,
            Phase::Running,
            Phase::Stopping,
            Phase::Stopped,
            Phase::Terminated,
        ]);
    } else {
        path.extend([Phase::Failed, Phase::Terminated]);
    }
    for step in path {
        life.step(step)?;
        trace.push(step);
    }
    if life.step(Phase::Starting).is_ok() {
        return Err(Phase::Starting);
    }
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::{Phase, legal, trace_for_launch};

    #[test]
    fn failed_worker_is_not_restarted() {
        let trace = trace_for_launch(false).expect("trace");
        assert_eq!(
            trace,
            vec![
                Phase::Created,
                Phase::Starting,
                Phase::Failed,
                Phase::Terminated,
            ]
        );
        let running = trace_for_launch(true).expect("running");
        assert_eq!(running.last().copied(), Some(Phase::Terminated));
        assert!(running.contains(&Phase::Running));
        assert!(!legal(Phase::Failed, Phase::Starting));
        assert!(!legal(Phase::Stopped, Phase::Running));
        assert!(!legal(Phase::Terminated, Phase::Ready));
        assert!(!legal(Phase::Created, Phase::Running));
        assert!(!legal(Phase::Running, Phase::Created));
    }
}
