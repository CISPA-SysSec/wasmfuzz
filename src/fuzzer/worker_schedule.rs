use std::time::{Duration, Instant};

use super::FuzzOpts;

#[allow(unused)]
struct Throttle {
    events: Vec<Instant>,
    interval: Duration,
    limit: usize,
}

#[allow(unused)]
impl Throttle {
    fn new(limit: usize, interval: Duration) -> Self {
        Self {
            events: Vec::new(),
            interval,
            limit,
        }
    }

    fn try_push(&mut self, event: Instant) -> bool {
        let interval_start = event.checked_sub(self.interval).unwrap();
        self.events.retain(|ev| ev > &interval_start);
        if self.events.len() < self.limit {
            self.events.push(event);
            true
        } else {
            false
        }
    }
}

pub(crate) struct WorkerSchedule {
    pub(crate) start: Instant,
    pub(crate) steps: u64,

    pub(crate) timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    timeout_steps: Option<u64>,

    last_cmin: Instant,
    last_print: Instant,
    last_poll: Instant,
    last_activity: Instant,

    print_interval: Duration,
    poll_interval: Duration,
    cmin_interval: Duration,
}

impl WorkerSchedule {
    pub(crate) fn new(opts: &FuzzOpts) -> Self {
        let now = Instant::now();
        Self {
            steps: 0,
            start: now,
            last_cmin: now,
            last_print: now,
            last_poll: now,
            last_activity: now,
            timeout: opts.t.timeout.as_deref().copied(),
            idle_timeout: opts.t.idle_timeout.as_deref().copied(),
            timeout_steps: opts.t.timeout_steps,
            print_interval: *opts.t.stats_interval,
            poll_interval: *opts.t.bus_poll_interval,
            cmin_interval: *opts.t.cmin_interval,
        }
    }

    pub(crate) fn start(&mut self) {
        self.start = Instant::now();
    }

    pub(crate) fn is_timeout(&self) -> bool {
        self.timeout
            .map(|timeout| self.start.elapsed() >= timeout)
            .unwrap_or(false)
            || self
                .timeout_steps
                .map(|timeout| self.steps >= timeout)
                .unwrap_or(false)
    }

    pub(crate) fn notify_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub(crate) fn is_idle_timeout(&self) -> bool {
        self.idle_timeout
            .map(|t| self.last_activity.elapsed() > t)
            .unwrap_or(false)
    }

    fn update_after_or(last: &mut Instant, interval: Duration, force: bool) -> bool {
        if last.elapsed() > interval || force {
            *last = Instant::now();
            true
        } else {
            false
        }
    }

    pub(crate) fn next_print(&mut self) -> bool {
        Self::update_after_or(&mut self.last_print, self.print_interval, false)
    }

    pub(crate) fn next_poll(&mut self) -> bool {
        Self::update_after_or(&mut self.last_poll, self.poll_interval, false)
    }

    pub(crate) fn next_cmin_or(&mut self, force: bool) -> bool {
        Self::update_after_or(&mut self.last_cmin, self.cmin_interval, force)
    }

    pub(crate) fn step(&mut self) {
        self.steps += 1;
    }
}
