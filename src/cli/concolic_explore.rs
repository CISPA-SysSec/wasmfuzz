use crate::{
    ir::{Location, ModuleSpec},
    HashSet,
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc, sync::Arc};

use crate::{
    concolic::{ConcolicEvent, ConcolicTrace},
    jit::{FeedbackOptions, JitFuzzingSession, Stats, TracingOptions},
};

use crate::concolic::{ConcolicProvider, ConcolicSolver};

#[derive(Debug)]
enum Work {
    Trace { input: Vec<u8> },
    Filter { trace_idx: usize },
    CheckSatNoConstraints { trace_idx: usize, event_idx: usize },
    CheckSatWithAllConstraints { trace_idx: usize, event_idx: usize },
    CheckSatWithConstraints { trace_idx: usize, event_idx: usize },
    VerifyMutated { input: Vec<u8> },
}

pub(crate) struct ConcolicExplorer<'a> {
    sess: JitFuzzingSession,
    mod_spec: Arc<ModuleSpec>,
    branches_taken: HashSet<Location>,
    branches_not_taken: HashSet<Location>,
    pub traces: Vec<ConcolicTrace>,
    mem_usage: usize,
    wq: VecDeque<Work>,
    solver_provider: &'a ConcolicProvider,
    solver: Option<(usize, Rc<RefCell<ConcolicSolver<'a>>>)>,
    pub new_finds: usize,
}

impl<'a> ConcolicExplorer<'a> {
    pub(crate) fn new(mod_spec: Arc<ModuleSpec>, solver_provider: &'a ConcolicProvider) -> Self {
        let mut sess = JitFuzzingSession::builder(mod_spec.clone())
            .feedback(FeedbackOptions {
                live_funcs: true,
                live_edges: true,
                perffuzz_func: true,
                perffuzz_edge: true,
                perffuzz_edge_global: true,
                cmpcov_hamming: true,
                ..FeedbackOptions::nothing()
            })
            .tracing(TracingOptions {
                concolic: true,
                ..TracingOptions::default()
            })
            .instruction_limit(Some(50_000_000))
            .build();
        let mut stats = Stats::default();
        sess.initialize(&mut stats);

        Self {
            sess,
            mod_spec,
            wq: VecDeque::new(),
            branches_taken: HashSet::default(),
            branches_not_taken: HashSet::default(),
            mem_usage: 0,
            traces: Vec::new(),
            solver: None,
            solver_provider,
            new_finds: 0,
        }
    }

    fn solver(&mut self, trace_idx: usize) -> Rc<RefCell<ConcolicSolver<'a>>> {
        match self.solver.as_ref() {
            Some((idx, solver)) if *idx == trace_idx => solver.clone(),
            _ => {
                let solver = self.solver_provider.new_solver(None).unwrap();
                let solver = Rc::new(RefCell::new(solver));
                self.solver = Some((trace_idx, solver.clone()));
                solver
            }
        }
    }

    pub(crate) fn feed(&mut self, input: Vec<u8>) {
        // process trace work first to filter path constraints early
        self.wq.push_front(Work::Trace { input });
    }

    pub(crate) fn has_work(&self) -> bool {
        !self.wq.is_empty()
    }
    pub(crate) fn work(&mut self) {
        if let Some(work) = self.wq.pop_front() {
            match &work {
                Work::Trace { input: _ } => eprintln!("Work::Trace"),
                Work::VerifyMutated { input: _ } => eprintln!("Work::VerifyMutated"),
                _ => eprintln!("{work:?}"),
            }
            match work {
                Work::Trace { input } => self.work_trace(input),
                Work::Filter { trace_idx } => self.work_filter(trace_idx),
                Work::CheckSatNoConstraints {
                    trace_idx,
                    event_idx,
                } => self.work_check_sat_no_constraints(trace_idx, event_idx),
                Work::CheckSatWithAllConstraints {
                    trace_idx,
                    event_idx,
                } => self.work_check_sat_with_all_constraints(trace_idx, event_idx),
                Work::CheckSatWithConstraints {
                    trace_idx,
                    event_idx,
                } => self.work_check_sat_with_constraints(trace_idx, event_idx),
                Work::VerifyMutated { input } => self.work_verify_mutated(input),
            }
        }
    }

    fn work_trace(&mut self, testcase: Vec<u8>) {
        crate::util::print_input_hexdump(&testcase);

        assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
        self.sess
            .run_reusable(&testcase, true, &mut Stats::default())
            .expect_ok();
        let _res = self
            .sess
            .run_tracing_fresh(&testcase, &mut Stats::default())
            .unwrap();
        let concolic_ctx = self
            .sess
            .tracing_stage
            .instance
            .as_ref()
            .unwrap()
            .vmctx
            .concolic
            .clone();
        self.mem_usage += concolic_ctx.approx_trace_mem_usage();
        // dbg!(concolic_ctx.events.len(), concolic_ctx.symvals.byte_len());
        let kinds = concolic_ctx
            .events
            .iter()
            .map(|ev| match ev {
                ConcolicEvent::PathConstraint { .. } => "PathConstraint",
                ConcolicEvent::MemoryConstraint { .. } => "MemoryConstraint",
                ConcolicEvent::TryAlternative { .. } => "TryAlternative",
                ConcolicEvent::TrySolveMemcmp { .. } => "TrySolveMemcmp",
                ConcolicEvent::TrySolveStrcmplike { .. } => "TrySolveStrcmplike",
            })
            .fold(crate::HashMap::<&str, usize>::default(), |mut acc, el| {
                *acc.entry(el).or_default() += 1;
                acc
            });
        dbg!(kinds);
        for ev in &concolic_ctx.events {
            if let ConcolicEvent::PathConstraint {
                location, taken, ..
            } = *ev
            {
                if taken {
                    self.branches_taken.insert(location);
                } else {
                    self.branches_not_taken.insert(location);
                }
            }
        }

        let trace_idx = self.traces.len();
        let trace = concolic_ctx.compact_to_trace(&testcase);
        self.traces.push(trace);

        let branches_to_flip = self
            .branches_taken
            .symmetric_difference(&self.branches_not_taken)
            .count();
        print!(
            "approx mem usage: {} ({}), branches to flip: {}    \r",
            humansize::format_size(
                self.traces
                    .iter()
                    .map(|trace| trace.symvals.byte_len())
                    .sum::<usize>(),
                humansize::DECIMAL
            ),
            humansize::format_size(self.mem_usage, humansize::DECIMAL),
            branches_to_flip
        );
        self.wq.push_back(Work::Filter { trace_idx });
    }

    fn work_filter(&mut self, trace_idx: usize) {
        let mut branches_to_flip: Vec<_> = self
            .branches_taken
            .symmetric_difference(&self.branches_not_taken)
            .cloned()
            .collect();
        branches_to_flip.sort();
        // for loc in branches_to_flip {
        let trace = &self.traces[trace_idx];
        dbg!(trace.events.len());
        for (event_idx, event) in trace.events.iter().enumerate() {
            // TODO: what about other events?
            dbg!(event);
            if let ConcolicEvent::PathConstraint {  .. } = *event {
                // if location == loc || true { // TODO
                self.wq.push_back(Work::CheckSatNoConstraints {
                    trace_idx,
                    event_idx,
                });
                // }
            }
        }
        // }
    }

    fn work_check_sat_no_constraints(&mut self, trace_idx: usize, event_idx: usize) {
        if self.is_filtered(trace_idx, event_idx) {
            return;
        }
        let solver = self.solver(trace_idx);
        let mut solver = solver.borrow_mut();
        let trace = &self.traces[trace_idx];
        let event = &trace.events[event_idx];
        // trace.symvals.debug_event(event);

        solver.provide_hint(&trace.input, &trace.event_inputs[event_idx]);

        println!("{}", self.mod_spec.format_location(event.location()));
        if let Ok(true) = solver.try_negate(event, &trace.symvals) {
            let mut solution = trace.input.clone();
            solver.apply_model(&mut solution);
            self.wq.push_front(Work::VerifyMutated { input: solution });
            // TODO: only queue this if verifymutated fails?
            self.wq.push_back(Work::CheckSatWithAllConstraints {
                trace_idx,
                event_idx,
            });
        }
    }

    fn work_check_sat_with_all_constraints(&mut self, trace_idx: usize, event_idx: usize) {
        if self.is_filtered(trace_idx, event_idx) {
            return;
        }
        let solver = self.solver(trace_idx);
        let mut solver = solver.borrow_mut();
        let trace = &self.traces[trace_idx];
        let event = &trace.events[event_idx];
        trace.symvals.debug_event(event);
        let mut submitted = HashSet::default();
        for (precond_event, _precond_inputs) in trace.events[..event_idx]
            .iter()
            .zip(trace.event_inputs[..event_idx].iter())
        {
            if solver
                .assert(precond_event, &trace.input, &trace.symvals, false)
                .is_err()
            {
                continue;
            }
        }
        match solver.try_negate(event, &trace.symvals) {
            Ok(true) => {
                let mut solution = trace.input.clone();
                solver.apply_model(&mut solution);
                if submitted.insert(solution.clone()) {
                    self.wq.push_front(Work::VerifyMutated { input: solution });
                }
            }
            Ok(false) => {
                self.wq.push_back(Work::CheckSatWithConstraints {
                    trace_idx,
                    event_idx,
                });
            }
            _ => todo!(),
        }
    }

    fn work_check_sat_with_constraints(&mut self, trace_idx: usize, event_idx: usize) {
        if self.is_filtered(trace_idx, event_idx) {
            return;
        }
        let solver = self.solver(trace_idx);
        let mut solver = solver.borrow_mut();
        let trace = &self.traces[trace_idx];
        let event = &trace.events[event_idx];
        trace.symvals.debug_event(event);
        let mut submitted = HashSet::default();
        let mut i = 0;
        let mut skip = 0;
        for (precond_event, precond_inputs) in trace.events[..event_idx]
            .iter()
            .zip(trace.event_inputs[..event_idx].iter())
            .rev()
        {
            // TODO: this is not correct!
            // if (trace.event_inputs[event_idx].clone() & precond_inputs).not_any() {
            //     continue;
            // }
            i += 1;
            if solver
                .assert(precond_event, &trace.input, &trace.symvals, false)
                .is_err()
            {
                continue;
            }

            if skip > 0 {
                skip -= 1;
                continue;
            } else if i > 30 {
                // skip = i - 30;
            }

            match solver.try_negate(event, &trace.symvals) {
                Ok(true) => {
                    let mut solution = trace.input.clone();
                    solver.apply_model(&mut solution);
                    if submitted.insert(solution.clone()) {
                        self.wq.push_front(Work::VerifyMutated { input: solution });
                    }
                }
                Ok(false) => {
                    return;
                }
                _ => todo!(),
            }
        }
    }

    fn work_verify_mutated(&mut self, input: Vec<u8>) {
        crate::util::print_input_hexdump(&input);

        let res = self.sess.run_reusable(&input, true, &mut Stats::new());
        res.expect_ok();
        if res.novel_coverage {
            self.new_finds += 1;
            /*
            println!("===============================================");
            panic!("new coverage via concolic");
            */
            self.feed(input);
            // TODO: send out?
        }
    }

    fn is_filtered(&self, trace_idx: usize, event_idx: usize) -> bool {
        let trace = &self.traces[trace_idx];
        let event = &trace.events[event_idx];
        self.branches_taken.contains(&event.location())
            && self.branches_not_taken.contains(&event.location())
            && false
    }
}
