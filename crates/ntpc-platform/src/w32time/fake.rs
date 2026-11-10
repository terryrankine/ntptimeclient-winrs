//! A scripted [`ServiceControl`] for tests. No OS calls.
//!
//! Built only with the `fake` feature or in this crate's tests. Every call
//! is logged with the service name, so a test can check the order of calls
//! and that only `w32time` was touched.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use super::{RunState, ServiceControl, StartType, SvcError, SvcState};

/// One logged call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `query(name)`.
    Query(String),
    /// `stop(name)`.
    Stop(String),
    /// `start(name)`.
    Start(String),
    /// `set_start_type(name, t)`.
    SetStartType(String, StartType),
    /// `pause(d)`.
    Pause,
    /// A mark a test pushes itself, for example when a record is persisted.
    Mark(&'static str),
}

/// The shared call log. Clone it into a persist closure to log the order.
pub type CallLog = Rc<RefCell<Vec<Call>>>;

/// The scripted service and the faults to inject.
#[derive(Debug, Clone)]
pub struct Script {
    /// `None` means the service does not exist.
    pub state: Option<SvcState>,
    /// Returned by `stop` instead of stopping.
    pub refuse_stop: Option<SvcError>,
    /// Queries that report `StopPending` after a stop before `Stopped`.
    /// `u32::MAX` means the stop never finishes.
    pub stop_pending_polls: u32,
    /// Returned by `set_start_type` instead of changing it.
    pub refuse_set_start: Option<SvcError>,
    /// Returned by `start` instead of starting.
    pub refuse_start: Option<SvcError>,
    /// Returned by every `query`.
    pub query_error: Option<SvcError>,
    /// The service comes back to `Running` right after it was disabled, as
    /// a policy or trigger restart would.
    pub restart_after_disable: bool,
}

impl Script {
    /// A running service with this start type and no faults.
    #[must_use]
    pub fn running(start: StartType) -> Self {
        Self::with(RunState::Running, start)
    }

    /// A service in `run` with `start` and no faults.
    #[must_use]
    pub fn with(run: RunState, start: StartType) -> Self {
        Self {
            state: Some(SvcState { run, start }),
            refuse_stop: None,
            stop_pending_polls: 0,
            refuse_set_start: None,
            refuse_start: None,
            query_error: None,
            restart_after_disable: false,
        }
    }

    /// No service of that name.
    #[must_use]
    pub fn missing() -> Self {
        Self {
            state: None,
            ..Self::running(StartType::Manual)
        }
    }
}

/// The fake. `query` takes `&self`, so the script sits in a `RefCell`.
#[derive(Debug)]
pub struct FakeScm {
    script: RefCell<Script>,
    /// Polls left before a sent stop finishes. `None` until `stop` runs, so a
    /// service scripted as `StopPending` stays pending.
    pending_left: RefCell<Option<u32>>,
    log: CallLog,
}

impl FakeScm {
    /// A fake that plays `script`.
    #[must_use]
    pub fn new(script: Script) -> Self {
        Self {
            script: RefCell::new(script),
            pending_left: RefCell::new(None),
            log: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// The shared log.
    #[must_use]
    pub fn log(&self) -> CallLog {
        Rc::clone(&self.log)
    }

    /// A copy of the calls so far.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.log.borrow().clone()
    }

    /// The service state now, `None` if missing.
    #[must_use]
    pub fn state(&self) -> Option<SvcState> {
        self.script.borrow().state
    }

    /// Changes the script between steps, for example to restart the service.
    pub fn script_mut(&mut self) -> std::cell::RefMut<'_, Script> {
        self.script.borrow_mut()
    }

    /// Whether any call mutated a service other than a query or a pause.
    #[must_use]
    pub fn mutated(&self) -> bool {
        self.log
            .borrow()
            .iter()
            .any(|c| matches!(c, Call::Stop(_) | Call::Start(_) | Call::SetStartType(_, _)))
    }

    fn push(&self, c: Call) {
        self.log.borrow_mut().push(c);
    }
}

impl ServiceControl for FakeScm {
    fn query(&self, name: &str) -> Result<SvcState, SvcError> {
        self.push(Call::Query(name.to_owned()));
        let mut s = self.script.borrow_mut();
        if let Some(e) = s.query_error.clone() {
            return Err(e);
        }
        let Some(state) = s.state.as_mut() else {
            return Err(SvcError::NotFound);
        };
        if state.run == RunState::StopPending {
            match self.pending_left.borrow_mut().as_mut() {
                Some(0) => state.run = RunState::Stopped,
                Some(left) if *left != u32::MAX => *left -= 1,
                _ => {}
            }
        }
        Ok(*state)
    }

    fn stop(&mut self, name: &str) -> Result<(), SvcError> {
        self.push(Call::Stop(name.to_owned()));
        let mut s = self.script.borrow_mut();
        if let Some(e) = s.refuse_stop.clone() {
            return Err(e);
        }
        let polls = s.stop_pending_polls;
        let Some(state) = s.state.as_mut() else {
            return Err(SvcError::NotFound);
        };
        if state.run == RunState::Stopped {
            return Err(SvcError::NotActive);
        }
        state.run = RunState::StopPending;
        *self.pending_left.borrow_mut() = Some(polls);
        Ok(())
    }

    fn start(&mut self, name: &str) -> Result<(), SvcError> {
        self.push(Call::Start(name.to_owned()));
        let mut s = self.script.borrow_mut();
        if let Some(e) = s.refuse_start.clone() {
            return Err(e);
        }
        let Some(state) = s.state.as_mut() else {
            return Err(SvcError::NotFound);
        };
        if state.start == StartType::Disabled {
            return Err(SvcError::Disabled);
        }
        if state.run == RunState::Running {
            return Err(SvcError::AlreadyRunning);
        }
        state.run = RunState::Running;
        Ok(())
    }

    fn set_start_type(&mut self, name: &str, t: StartType) -> Result<(), SvcError> {
        self.push(Call::SetStartType(name.to_owned(), t));
        let mut s = self.script.borrow_mut();
        if let Some(e) = s.refuse_set_start.clone() {
            return Err(e);
        }
        let restart = s.restart_after_disable;
        let Some(state) = s.state.as_mut() else {
            return Err(SvcError::NotFound);
        };
        state.start = t;
        if restart && t == StartType::Disabled {
            state.run = RunState::Running;
        }
        Ok(())
    }

    fn pause(&mut self, _d: Duration) {
        self.push(Call::Pause);
    }
}
