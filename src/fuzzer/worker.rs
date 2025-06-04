use crate::instrumentation::InstrumentationSnapshot;
use crate::jit::tracing::CmpLog;
use crate::HashSet;
use std::collections::VecDeque;
use std::{sync::Arc, time::Instant};

use crate::simple_bus::MessageBus;
use libafl::corpus::CorpusId;
use libafl::inputs::ResizableMutator;
use libafl::mutators::{havoc_mutations, HavocScheduledMutator, StdMOptMutator};
use libafl::observers::CmplogBytes;
use libafl::stages::StageId;
use libafl::state::HasCurrentStageId;
use libafl::state::{HasSolutions, Stoppable};
use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
    inputs::BytesInput,
    mutators::Mutator,
    observers::{CmpValues, CmpValuesMetadata},
    state::{HasCorpus, HasMaxSize, HasRand},
    HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    rands::{Rand, StdRand},
    serdeany::SerdeAnyMap,
};

use rand::prelude::SliceRandom;

use crate::jit::{JitFuzzingSession, SwarmConfig, TracingOptions};
use crate::{ir::ModuleSpec, jit::Stats};

use super::exhaustive::QueuedInputMutation;
use super::worker_schedule::WorkerSchedule;
use super::FuzzOpts;

#[derive(Debug, Clone)]
pub(crate) enum Message {
    Testcase { input: Arc<Vec<u8>>, sender: usize },
    Exit,
}

pub(crate) struct Worker {
    idx: usize,
    opts: FuzzOpts,
    pub corpus: InMemoryCorpus<BytesInput>,
    pub solutions: InMemoryCorpus<BytesInput>,
    rand: StdRand,
    pub stats: Stats,
    bus: Arc<MessageBus<Message>>,
    bus_rx: crossbeam_channel::Receiver<Message>,
    metadata: SerdeAnyMap,
    pub(crate) sess: JitFuzzingSession,
    exhaustive_queue: VecDeque<Box<dyn QueuedInputMutation>>,
    pub(crate) schedule: WorkerSchedule,
    last_crasher: Option<Vec<u8>>,
    corpus_id: Option<CorpusId>,
    stage_id_stack: Vec<StageId>,
    stage_depth: usize,
    stop_requested: bool,
}

impl Worker {
    pub(crate) fn new(
        mod_spec: Arc<ModuleSpec>,
        opts: FuzzOpts,
        bus: Arc<MessageBus<Message>>,
        idx: usize,
        orc: Option<super::orc::OrchestratorHandle>,
    ) -> Self {
        tracy_full::zone!("Worker::new");
        let rng_seed = opts.rng_seed.unwrap_or_else(current_nanos);
        let rand = StdRand::with_seed(rng_seed);

        let mut schedule = WorkerSchedule::new(&opts);

        let sess = match orc {
            Some(ref handle) => {
                let config = handle.suggest();
                eprintln!("got config: {config:#?}");
                schedule.timeout = Some(config.timeout);
                JitFuzzingSession::builder(mod_spec.clone())
                    .passes_generator(Arc::new(config.passes))
                    .tracing(TracingOptions {
                        stdout: true,
                        cmplog: *opts.x.use_cmplog,
                        concolic: false, // TODO
                    })
                    .run_from_snapshot(*opts.x.run_from_snapshot)
                    .swarm(config.swarm)
                    .build()
            }
            None => JitFuzzingSession::builder(mod_spec.clone())
                .feedback(opts.i.to_feedback_opts())
                .tracing(TracingOptions {
                    stdout: true,
                    cmplog: *opts.x.use_cmplog,
                    concolic: *opts.x.use_concolic,
                })
                .swarm(SwarmConfig::from_instruction_limit(
                    opts.x.instruction_limit,
                ))
                .run_from_snapshot(*opts.x.run_from_snapshot)
                .input_size_limit(opts.g.input_size_limit as u32)
                .build(),
        };

        let mut worker = Self {
            schedule,
            idx,
            corpus: InMemoryCorpus::<BytesInput>::new(),
            solutions: InMemoryCorpus::<BytesInput>::new(),
            rand,
            bus_rx: bus.subscribe(),
            bus,
            metadata: SerdeAnyMap::new(),
            stats: Stats::new(),
            sess,
            exhaustive_queue: VecDeque::new(),
            last_crasher: None,
            corpus_id: None,
            stage_depth: 0,
            stage_id_stack: Vec::new(),
            opts,
            stop_requested: false,
        };
        // TODO: move this somewhere else?
        if let Some(ref orc) = orc {
            let corpus = orc.fetch_corpus();
            if !corpus.is_empty() {
                worker.sess.reset_pass_coverage();
                worker.sess.initialize(&mut worker.stats);
                eprintln!("running orc's inputs ...");
                for input in corpus {
                    if input.len() > worker.sess.swarm.input_alloc_size() {
                        continue;
                    }
                    // NOTE: we don't need to trace here if we're going to throw them away anyways!
                    let res = worker.on_corpus(&input, false);
                    if matches!(res, Err(_) | Ok(InputVerdict::Crashed)) {
                        break;
                    }
                }
                eprintln!(
                    "after fetch_corpus: {} edges",
                    worker.sess.get_edge_cov().unwrap_or(0)
                );
                for _ in 0..10 {
                    if !worker.inmemory_cmin(false) {
                        break;
                    }
                }
                eprintln!(
                    "after inmem_cmin: {} edges",
                    worker.sess.get_edge_cov().unwrap_or(0)
                );
            }
        }
        worker
    }

    // Save input to our corpus if it produces new coverage
    // Note: this should be the first time we run the input
    fn on_corpus(&mut self, input: &[u8], is_seed: bool) -> Result<InputVerdict, libafl::Error> {
        tracy_full::zone!("Worker::on_corpus");
        let ignore_crashes = *self.opts.x.fuzz_through_crashes;
        if !*self.opts.x.run_from_snapshot {
            let res = self.sess.run_reusable(input, false, &mut self.stats);
            if res.is_crash() && !ignore_crashes {
                self.last_crasher = Some(input.to_vec());
                return Ok(InputVerdict::Crashed);
            }
            if is_seed && !res.novel_coverage {
                return Ok(InputVerdict::NotInteresting);
            }
        }

        // make sure we catch inputs that crash on fresh instances but not on used ones (TODO?)
        let res = self.sess.run_reusable_fresh(input, false, &mut self.stats);
        if res.is_crash() && !ignore_crashes {
            self.last_crasher = Some(input.to_vec());
            return Ok(InputVerdict::Crashed);
        }

        if !res.novel_coverage {
            return Ok(InputVerdict::NotInteresting);
        }

        self.add_to_corpus(input, is_seed)?;
        Ok(InputVerdict::Interesting)
    }

    // (unconditionally) save this input to our corpus
    fn add_to_corpus(&mut self, input: &[u8], is_seed: bool) -> Result<(), libafl::Error> {
        tracy_full::zone!("Worker::add_to_corpus");
        let mut testcase: Testcase<BytesInput> = Testcase::new(input.into());

        self.sess.reset_pass_coverage_keep_saved();
        let _ = self.sess.run(input, &mut self.stats);
        let coverage_snapshot = InstrumentationSnapshot::from(&self.sess.passes);
        if false {
            let total = coverage_snapshot
                .snapshots
                .iter()
                .map(|x| x.mem_usage())
                .sum::<usize>();
            eprintln!(
                "Snapshot Mem Usage: {}",
                humansize::format_size(total, humansize::DECIMAL)
            );
            for (pass, snapshot) in self
                .sess
                .passes
                .iter()
                .zip(coverage_snapshot.snapshots.iter())
            {
                eprintln!(
                    "- {}: {}",
                    pass.shortcode(),
                    humansize::format_size(snapshot.mem_usage(), humansize::DECIMAL),
                );
            }
        }
        testcase.metadata_map_mut().insert(coverage_snapshot);

        self.gather_trace_metadata(input, &mut testcase);
        self.corpus.add(testcase)?;
        if self.opts.verbose_corpus {
            crate::util::print_input_hexdump(input);
        }

        self.save_input(input);

        if *self.opts.x.exhaustive_stage && !is_seed {
            if input.len() <= 1024 {
                self.exhaustive_queue.push_back(Box::new(
                    super::exhaustive::ReplaceEveryInputByte::new(input, &mut self.rand),
                ));
            } else if input.len() <= 8192 {
                self.exhaustive_queue
                    .push_back(Box::new(super::exhaustive::FlipEveryBit::new(input)));
            }
        }

        Ok(())
    }

    fn save_input(&self, input: &[u8]) {
        if let Some(path) = self.opts.g.out_dir() {
            let mut inp_path = path.clone();
            let inphash = md5::compute(input);
            inp_path.push(format!("{inphash:x}"));
            if !inp_path.is_file() {
                let _ = std::fs::create_dir_all(path);
                let _ = std::fs::write(&inp_path, input);
                println!("saved {inp_path:?}");
            }
        }
    }

    // TODO: defer tracing? some corpus inputs are not kept around for long
    //       => tracing these could become expensive?
    fn gather_trace_metadata(&mut self, input: &[u8], testcase: &mut Testcase<BytesInput>) {
        tracy_full::zone!("Worker::gather_trace_metadata");
        if *self.opts.x.use_cmplog {
            let _ = self.sess.run_tracing_fresh(input, &mut self.stats);
            let feedback = self.sess.tracing_stage.feedback();

            let mut combined = HashSet::default();

            for items in feedback.cmplog.values() {
                if items.len() > 420 {
                    continue;
                }
                let mut vals = HashSet::default();
                for el in items {
                    let (a, b) = match el {
                        &CmpLog::U16(a, b) => (a as u64, b as u64),
                        &CmpLog::U32(a, b) => (a as u64, b as u64),
                        &CmpLog::U64(a, b) => (a, b),
                        CmpLog::Memcmp(_, _) => continue,
                    };
                    vals.insert(a);
                    vals.insert(b);
                }
                let looplike = |el: u64| {
                    for i in 1..2 {
                        if let Some(x) = el.checked_add(i) {
                            if !vals.contains(&x) {
                                return false;
                            }
                        }
                        if let Some(x) = el.checked_sub(i) {
                            if !vals.contains(&x) {
                                return false;
                            }
                        }
                    }
                    true
                };
                for el in items {
                    let (a, b) = match el {
                        &CmpLog::U16(a, b) => (a as u64, b as u64),
                        &CmpLog::U32(a, b) => (a as u64, b as u64),
                        &CmpLog::U64(a, b) => (a, b),
                        CmpLog::Memcmp(_, _) => {
                            combined.insert(el.clone());
                            continue;
                        }
                    };
                    if !looplike(a) && !looplike(b) {
                        combined.insert(el.clone());
                    }
                }
            }

            // for el in &combined {
            //     eprintln!("{:x?}", el);
            // }

            fn cmplog_to_cmpvalues(el: &CmpLog) -> CmpValues {
                fn make_cmplog_bytes(data: &[u8]) -> CmplogBytes {
                    let mut buf = [0; 32];
                    let len = std::cmp::min(data.len(), 32);
                    buf[..len].copy_from_slice(&data[..len]);
                    CmplogBytes::from_buf_and_len(buf, len as u8)
                }
                match el {
                    // TODO: track if values are const
                    &CmpLog::U16(a, b) => CmpValues::U16((a, b, false)),
                    &CmpLog::U32(a, b) => CmpValues::U32((a, b, false)),
                    &CmpLog::U64(a, b) => CmpValues::U64((a, b, false)),
                    CmpLog::Memcmp(a, b) => {
                        CmpValues::Bytes((make_cmplog_bytes(a), make_cmplog_bytes(b)))
                    }
                }
            }

            // TODO: filter for entries that appear in the input?
            testcase.metadata_map_mut().insert(CmpValuesMetadata {
                list: combined.iter().map(cmplog_to_cmpvalues).collect(),
            });
        }
    }

    pub(crate) fn run(&mut self) -> Result<WorkerExit, libafl::Error> {
        let res = self.run_();
        println!("{:?} {}", res, self.stats.format(&self.opts.thread_name));
        res
    }

    fn run_(&mut self) -> Result<WorkerExit, libafl::Error> {
        let ignore_crashes = *self.opts.x.fuzz_through_crashes;
        let first_run = self.corpus.is_empty();
        if first_run {
            self.sess.reset_pass_coverage();
            self.sess.initialize(&mut self.stats);
            match self.initialize_corpus() {
                Ok(_) => (),
                Err(CrashOrLibAFLError::Crash) if ignore_crashes => (),
                Err(CrashOrLibAFLError::Crash) => return Ok(WorkerExit::CrashFound),
                Err(CrashOrLibAFLError::LibAFLError(e)) => return Err(e),
            };
            if self.corpus.is_empty() {
                return Ok(WorkerExit::InvalidSwarm);
            }
            if self.schedule.is_timeout() {
                panic!("timeout hit during corpus initialization");
            }
            self.schedule.notify_activity();
            self.schedule.start();
        } else if self.schedule.is_timeout() {
            return Ok(WorkerExit::Timeout);
        }

        println!("starting with {} corpus entries...", self.corpus.count());

        let mutations = havoc_mutations(); // .merge(tokens_mutations());
        let mutations = (super::i2s_patches::I2SRandReplace, mutations);

        let mut mutator: Box<dyn Mutator<BytesInput, Self>> = if *self.opts.x.mopt {
            Box::new(StdMOptMutator::new(self, mutations, 3, 7)?)
        } else {
            Box::new(HavocScheduledMutator::with_max_stack_pow(mutations, 1)) // default is six max_iterations
        };

        let mut input = BytesInput::new(
            self.corpus
                .get(self.corpus.first().unwrap())?
                .borrow_mut()
                .load_input(&self.corpus)?
                .as_ref()
                .to_vec(),
        );

        let mut corpus_additions_since_cmin = 0u64;
        let mut sticky_input = None;
        let mut sticky_cooldown = 0u32;
        const A_FEW_EXECS: u32 = 4096; // We want these to complete in < ~1ms
        loop {
            tracy_full::zone!("Worker loop");
            let mut interesting = false;

            let mut exhaustive_queue = std::mem::take(&mut self.exhaustive_queue);
            if !exhaustive_queue.is_empty() {
                // TODO: refactor? keep list of corpus input hashes somewhere? would greatly simplify this stuff.
                let mut _corpus = HashSet::default();
                for i in self.corpus.ids() {
                    let entry = self.corpus.get(i).unwrap();
                    _corpus.insert(entry.borrow().input().as_ref().unwrap().as_ref().to_vec());
                }
                exhaustive_queue.retain(|el| _corpus.contains(el.input()));
                exhaustive_queue.retain(|el| el.has_next());
            }
            if let Some(mut det) = exhaustive_queue.pop_front() {
                input.drain(..);
                input.extend(det.input());
                let mut execs = A_FEW_EXECS / det.mutation_overhead();
                if execs == 0 {
                    execs = 1;
                }
                if std::env::var("EXHAUSTIVE_BLOCK").as_deref().unwrap_or("0") == "1" {
                    execs = u32::MAX;
                }
                'fast_det: for _ in 0..execs {
                    if !det.has_next() {
                        break 'fast_det;
                    }
                    self.stats.exhaustive_execs += 1;
                    det.next(input.as_mut());
                    self.schedule.step();
                    let _interesting = match self.run_input(input.as_ref())? {
                        InputVerdict::Interesting => true,
                        InputVerdict::NotInteresting => false,
                        InputVerdict::Crashed if ignore_crashes => unreachable!(),
                        InputVerdict::Crashed => return Ok(WorkerExit::CrashFound),
                    };
                    if _interesting {
                        self.stats.exhaustive_finds += 1;
                        if let Some(credit) = det.credit() {
                            println!("interesting deterministic/{credit}");
                        }
                        interesting = true;
                        corpus_additions_since_cmin += 1;
                        // TODO: move this to a proper power schedule?
                        // TODO: refactor
                        sticky_input = Some(self.corpus.count() - 1);
                        sticky_cooldown = A_FEW_EXECS;
                        break 'fast_det;
                    }
                    if !det.revert(input.as_mut()) {
                        input.drain(..);
                        input.extend(det.input());
                    }
                }
                exhaustive_queue.push_back(det);
            }
            let new_entries = std::mem::replace(&mut self.exhaustive_queue, exhaustive_queue);
            self.exhaustive_queue.extend(new_entries);

            'fast: for _ in 0..A_FEW_EXECS {
                if interesting && self.exhaustive_queue.len() <= 1 {
                    break;
                }
                let corp_count = self.corpus.count();
                // TODO(tuning): stacking prob is low?
                if corp_count > 0 && self.rand.next() & 1 == 0 {
                    let corpus_idx = self.rand.below(corp_count.try_into().unwrap());
                    let corpus_idx = self.corpus.nth(sticky_input.unwrap_or(corpus_idx));
                    input.drain(..);
                    input.extend(
                        self.corpus
                            .get(corpus_idx)?
                            .borrow_mut()
                            .load_input(&self.corpus)?
                            .as_ref(),
                    );
                    *self.corpus.current_mut() = Some(corpus_idx);
                    sticky_cooldown = sticky_cooldown.saturating_sub(1);
                    if sticky_cooldown == 0 {
                        sticky_input = None;
                    }
                }

                {
                    let start = Instant::now();
                    // Note: optionally retrace input before mutating?
                    mutator.mutate(self, &mut input)?;
                    assert!(input.as_ref().len() <= self.sess.swarm.input_alloc_size());
                    self.stats.wall_mutate_ns += start.elapsed().as_nanos() as u64;
                }

                self.schedule.step();
                let _interesting = match self.run_input(input.as_ref())? {
                    InputVerdict::Interesting => true,
                    InputVerdict::NotInteresting => false,
                    InputVerdict::Crashed if ignore_crashes => unreachable!(),
                    InputVerdict::Crashed => return Ok(WorkerExit::CrashFound),
                };
                if _interesting {
                    self.schedule.notify_activity();
                    interesting = true;
                    corpus_additions_since_cmin += 1;
                    // TODO: move this to a proper power schedule / favoured inputs?
                    sticky_input = Some(self.corpus.count() - 1);
                    sticky_cooldown = A_FEW_EXECS;
                }
                mutator.post_exec(self, None)?;
                if _interesting {
                    break 'fast;
                }
            }

            if self.schedule.next_poll() {
                while let Ok(msg) = self.bus_rx.try_recv() {
                    self.stats.bus_rx += 1;
                    match msg {
                        Message::Testcase { input, sender } => {
                            if *self.opts.x.ignore_bus_inputs {
                                continue;
                            }
                            if sender != self.idx {
                                self.schedule.notify_activity();
                                match self.on_corpus(&input, false)? {
                                    InputVerdict::Interesting => {
                                        self.stats.finds_imported += 1;
                                    }
                                    InputVerdict::Crashed => return Ok(WorkerExit::CrashFound),
                                    _ => {}
                                };
                            }
                        }
                        Message::Exit => {
                            return Ok(WorkerExit::GotExitSignal);
                        }
                    }
                }
            }

            // periodic stuff
            if self.schedule.next_print() {
                println!("{}", self.stats.format(&self.opts.thread_name));
            }

            let force_cmin = corpus_additions_since_cmin >= self.opts.x.cmin_after_corpus_additions;
            if force_cmin {
                self.opts.x.cmin_after_corpus_additions += 1;
            }
            // note: this breaks deterministic (single-core) runs with --rng-seed
            if self.schedule.next_cmin_or(force_cmin) {
                self.inmemory_cmin(!force_cmin);
                corpus_additions_since_cmin = 0;
                sticky_input = None;
            }

            if self.schedule.is_timeout() || self.stop_requested {
                return Ok(WorkerExit::Timeout);
            }

            if self.schedule.is_idle_timeout() {
                return Ok(WorkerExit::IdleTimeout);
            }
        }
    }

    fn initialize_corpus(&mut self) -> Result<(), CrashOrLibAFLError> {
        tracy_full::zone!("Worker::initialize_corpus");
        self.corpus = InMemoryCorpus::new();

        // Note: The highest-seen approach leaves an average of log(N) * #metric intermediate
        // entries. They'll be thrown out in subsequent corpus minimization passes.
        if let Some(path) = &self.opts.g.seed_dir() {
            let mut dir = std::fs::read_dir(path)
                .expect("failed to list seeds dir")
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            dir.shuffle(&mut self.rand);
            for entry in dir {
                if self.opts.x.corpus_drop_pct as usize > self.rand.below(101.try_into().unwrap()) {
                    println!(
                        "{:?}: Dropped by chance ({}%)",
                        entry, self.opts.x.corpus_drop_pct
                    );
                    continue;
                }
                let input =
                    std::fs::read(entry.path()).expect("failed to read corpus entry (racy rm?)");
                if input.len() > self.sess.swarm.input_alloc_size() {
                    println!(
                        "{:?}: Skipping due to size limit ({} > {})",
                        entry,
                        input.len(),
                        self.sess.swarm.input_alloc_size()
                    );
                    continue;
                }
                // eprintln!("on_corpus: {:?}", entry.file_name());
                CrashOrLibAFLError::convert(self.on_corpus(&input, true))?;
                if self.schedule.is_timeout() {
                    eprintln!("[WARN] timeout during initialize_corpus");
                    break;
                }
            }
        }
        if self.corpus.is_empty() {
            println!("[warn] adding dummy input to corpus...");
            CrashOrLibAFLError::convert(self.on_corpus(b"YELLOW SUBMARINE", false))?;
            assert!(
                !self.corpus.is_empty() || self.sess.swarm.discard_short_circuit_coverage,
                "we should be saving our dummy input! (fuel limit too tight?)"
            );
        }
        Ok(())
    }

    fn run_input(&mut self, input: &[u8]) -> Result<InputVerdict, libafl::Error> {
        tracy_full::zone!("Worker::run_input");
        assert!(input.len() <= self.sess.swarm.input_alloc_size());
        let res = self.sess.run(input, &mut self.stats);
        let ignore_crashes = *self.opts.x.fuzz_through_crashes;
        if res.is_crash() && !ignore_crashes {
            self.save_input(input);
            self.bus.send(Message::Testcase {
                input: Arc::new(input.to_vec()),
                sender: self.idx,
            });
            self.stats.bus_tx += 1;
            self.corpus.add(Testcase::new(input.into()))?;
            self.bus.send(Message::Exit);
            self.solutions
                .add(Testcase::new(BytesInput::new(input.to_vec())))
                .unwrap();
            self.last_crasher = Some(input.to_vec());
            return Ok(InputVerdict::Crashed);
        }
        if res.novel_coverage {
            res.print_cov_update(&self.sess, self.corpus.count());
            // Add the input to the main corpus
            self.add_to_corpus(input, false)?;
            self.bus.send(Message::Testcase {
                input: Arc::new(input.to_vec()),
                sender: self.idx,
            });
            self.stats.bus_tx += 1;
            self.stats.finds_own += 1;
        };
        Ok(match res.novel_coverage {
            true => InputVerdict::Interesting,
            false => InputVerdict::NotInteresting,
        })
    }

    pub(crate) fn inmemory_cmin(&mut self, is_periodic: bool) -> bool {
        tracy_full::zone!("Worker::inmemory_cmin");
        if is_periodic {
            println!(
                "starting periodic in-memory cmin with {} entries",
                self.corpus.count()
            );
        }

        let mut corpus_idxs = self.corpus.ids().collect::<Vec<_>>();
        let mut to_remove = Vec::new();
        let mut dropped_randomly = 0;

        corpus_idxs.shuffle(&mut self.rand);

        let mut cov_acc = InstrumentationSnapshot::empty_from(&self.sess.passes);

        for idx in corpus_idxs {
            let drop_by_chance = is_periodic
                && self.opts.x.corpus_cmin_drop_pct
                    > self.rand.below(100.try_into().unwrap()) as u64;
            if drop_by_chance {
                dropped_randomly += 1;
                to_remove.push(idx);
                continue;
            }
            let testcase = self.corpus.get(idx).unwrap().borrow();
            let cov_snapshot = testcase
                .metadata_map()
                .get::<InstrumentationSnapshot>()
                .expect("missing coverage snapshot in corpus testcase metadata");
            if !cov_acc.update_with(cov_snapshot) {
                to_remove.push(idx);
            }
        }

        // pop from the back
        to_remove.sort_unstable();
        to_remove.reverse();
        for &idx in &to_remove {
            self.corpus_mut().remove(idx).unwrap();
        }

        if dropped_randomly != 0 {
            // coverage might have reduced by dropping random inputs!
            self.sess.reset_pass_coverage();
            self.sess.initialize(&mut self.stats);

            for idx in self.corpus.ids() {
                let testcase = self.corpus.get(idx).unwrap().borrow();
                let input = testcase.input().as_ref().unwrap().as_ref();
                let _ = self.sess.run_reusable_fresh(input, false, &mut self.stats);
            }
        }

        if is_periodic {
            if dropped_randomly != 0 {
                println!(
                    "-> {} entries ({} dropped randomly)",
                    self.corpus.count(),
                    dropped_randomly
                );
            } else {
                println!("-> {} entries", self.corpus.count());
            }
        }
        *self.corpus.current_mut() = None;

        if self.corpus.is_empty() {
            self.sess.reset_pass_coverage();
            println!("[warn] adding dummy input to corpus...");
            let _ = CrashOrLibAFLError::convert(self.on_corpus(b"YELLOW SUBMARINE", false));
        }

        !to_remove.is_empty()
    }
}

impl serde::Serialize for Worker {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        unimplemented!()
    }
}
impl<'de> serde::Deserialize<'de> for Worker {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        unimplemented!()
    }
}

impl HasRand for Worker {
    type Rand = StdRand;
    fn rand(&self) -> &StdRand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut StdRand {
        &mut self.rand
    }
}

impl HasCorpus<BytesInput> for Worker {
    type Corpus = InMemoryCorpus<BytesInput>;
    fn corpus(&self) -> &InMemoryCorpus<BytesInput> {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut InMemoryCorpus<BytesInput> {
        &mut self.corpus
    }
}

impl HasCurrentCorpusId for Worker {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), libafl::Error> {
        self.corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), libafl::Error> {
        self.corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, libafl::Error> {
        Ok(self.corpus_id)
    }
}

impl HasCurrentStageId for Worker {
    fn set_current_stage_id(&mut self, idx: StageId) -> Result<(), libafl::Error> {
        // ensure we are in the right frame
        if self.stage_depth != self.stage_id_stack.len() {
            return Err(libafl::Error::illegal_state(
                "stage not resumed before setting stage",
            ));
        }
        self.stage_id_stack.push(idx);
        Ok(())
    }

    fn clear_stage_id(&mut self) -> Result<(), libafl::Error> {
        self.stage_id_stack.pop();
        // ensure we are in the right frame
        if self.stage_depth != self.stage_id_stack.len() {
            return Err(libafl::Error::illegal_state(
                "we somehow cleared too many or too few states!",
            ));
        }
        Ok(())
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, libafl::Error> {
        Ok(self.stage_id_stack.get(self.stage_depth).copied())
    }

    fn on_restart(&mut self) -> Result<(), libafl::Error> {
        self.stage_depth = 0; // reset the stage depth so that we may resume inward
        Ok(())
    }
}

impl HasSolutions<BytesInput> for Worker {
    type Solutions = InMemoryCorpus<BytesInput>;
    fn solutions(&self) -> &InMemoryCorpus<BytesInput> {
        &self.solutions
    }

    fn solutions_mut(&mut self) -> &mut InMemoryCorpus<BytesInput> {
        &mut self.solutions
    }
}

impl HasMaxSize for Worker {
    fn max_size(&self) -> usize {
        self.sess.swarm.input_alloc_size()
    }

    fn set_max_size(&mut self, _max_size: usize) {
        panic!()
    }
}

impl HasMetadata for Worker {
    fn metadata_map(&self) -> &libafl_bolts::serdeany::SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut libafl_bolts::serdeany::SerdeAnyMap {
        &mut self.metadata
    }
}

impl Stoppable for Worker {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InputVerdict {
    Interesting,
    NotInteresting,
    Crashed,
}

#[derive(Debug)]
enum CrashOrLibAFLError {
    Crash,
    LibAFLError(libafl::Error),
}

impl CrashOrLibAFLError {
    fn convert(res: Result<InputVerdict, libafl::Error>) -> Result<bool, Self> {
        match res {
            Ok(InputVerdict::Interesting) => Ok(true),
            Ok(InputVerdict::NotInteresting) => Ok(false),
            Ok(InputVerdict::Crashed) => Err(Self::Crash),
            Err(e) => Err(Self::LibAFLError(e)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WorkerExit {
    CrashFound,
    GotExitSignal,
    Timeout,
    IdleTimeout,
    InvalidSwarm,
}
