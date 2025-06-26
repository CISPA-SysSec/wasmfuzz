use rand::{Rng, seq::SliceRandom};

pub trait QueuedInputMutation {
    fn input(&self) -> &[u8];
    // next() is called on a buffer that was previously initialized with input()
    fn next(&mut self, input: &mut [u8]);
    fn has_next(&self) -> bool;
    fn revert(&self, _input: &mut [u8]) -> bool {
        false
    }
    fn credit(&self) -> Option<String> {
        None
    }
    fn mutation_overhead(&self) -> u32 {
        1
    }
}

pub(crate) struct FlipEveryBit {
    input: Vec<u8>,
    current_position: usize,
    current_byte: u8,
    changed_position: usize,
}

impl FlipEveryBit {
    pub(crate) fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            current_position: 0,
            current_byte: 1,
            changed_position: 0,
        }
    }
}

impl QueuedInputMutation for FlipEveryBit {
    fn input(&self) -> &[u8] {
        &self.input
    }

    fn has_next(&self) -> bool {
        self.current_position < self.input.len()
    }

    fn next(&mut self, input: &mut [u8]) {
        input[self.current_position] ^= self.current_byte;
        self.changed_position = self.current_position;
        if self.current_byte == 1 << 7 {
            self.current_position += 1;
        }
        self.current_byte = self.current_byte.rotate_left(1);
    }

    fn revert(&self, input: &mut [u8]) -> bool {
        input[self.changed_position] = self.input[self.changed_position];
        true
    }

    fn credit(&self) -> Option<String> {
        Some(format!("flip-every-bit @ {:#x}", self.changed_position))
    }
}

pub(crate) struct ReplaceEveryInputByte {
    input: Vec<u8>,
    schedule_index: usize,
    byte_schedule_index: u8,
    changed_position: usize,

    schedule: Vec<u16>,
    schedule_byte: [u8; 256],
}

impl ReplaceEveryInputByte {
    pub(crate) fn new<R: Rng>(input: &[u8], rng: &mut R) -> Self {
        let mut schedule: Vec<u16> = (0..input.len() as u16).collect();
        let mut schedule_byte: [u8; 256] = (0..=0xffu8).collect::<Vec<_>>().try_into().unwrap();
        schedule.shuffle(rng);
        schedule_byte.shuffle(rng);
        Self {
            input: input.to_vec(),
            schedule_index: 0,
            byte_schedule_index: 0,
            changed_position: 0,
            schedule,
            schedule_byte,
        }
    }
}

impl QueuedInputMutation for ReplaceEveryInputByte {
    fn input(&self) -> &[u8] {
        &self.input
    }

    fn has_next(&self) -> bool {
        self.schedule_index < self.input.len()
    }

    fn next(&mut self, input: &mut [u8]) {
        let pos = self.schedule[self.schedule_index] as usize;
        input[pos] = self.schedule_byte[self.byte_schedule_index as usize];
        self.changed_position = pos;
        if self.byte_schedule_index == 0xff {
            self.schedule_index += 1;
        }
        self.byte_schedule_index = self.byte_schedule_index.wrapping_add(1);
    }

    fn revert(&self, input: &mut [u8]) -> bool {
        input[self.changed_position] = self.input[self.changed_position];
        true
    }

    fn credit(&self) -> Option<String> {
        Some(format!("replace-every-byte @ {:#x}", self.changed_position))
    }
}

#[cfg(feature = "concolic_bitwuzla")]
pub(crate) use concolic_bitwuzla::*;
#[cfg(feature = "concolic_bitwuzla")]
mod concolic_bitwuzla {
    // TODO: refactor/move from here.
    // TODO: slice path constraints? we currently apply all, even for unrelated inputs.
    // => a single unsupported fp constraint breaks all subsequent path constrains

    use super::*;
    use crate::{
        concolic::{self, ConcolicEvent, ConcolicTrace},
        ir::ModuleSpec,
    };
    use std::{collections::VecDeque, sync::Arc};

    pub(crate) struct ConcolicFlipPathsWithBitwuzla {
        input: Vec<u8>,
        events: VecDeque<ConcolicEvent>,
        solver: concolic::BitwuzlaSolver,
        trace: ConcolicTrace,
        current: Option<ConcolicEvent>,
    }

    impl ConcolicFlipPathsWithBitwuzla {
        pub(crate) fn new(input: &[u8], trace: ConcolicTrace, spec: Arc<ModuleSpec>) -> Self {
            ConcolicFlipPathsWithBitwuzla {
                input: input.to_vec(),
                events: trace.events.iter().cloned().collect(),
                solver: concolic::BitwuzlaSolver::new(Some(spec)),
                current: None,
                trace,
            }
        }
    }

    impl QueuedInputMutation for ConcolicFlipPathsWithBitwuzla {
        fn input(&self) -> &[u8] {
            &self.input
        }
        fn has_next(&self) -> bool {
            !self.events.is_empty()
        }
        fn next(&mut self, input: &mut [u8]) {
            let event = self.events.pop_front().unwrap();
            if self
                .solver
                .try_negate(&event, &self.trace.symvals)
                .unwrap_or(false)
            {
                self.solver.apply_model(input);
            }
            let _ = self
                .solver
                .assert(&event, &self.input, &self.trace.symvals, false);
            self.current = Some(event);
        }
        fn credit(&self) -> Option<String> {
            self.current
                .as_ref()
                .map(|el| format!("concolic-model: {:?}", el))
        }
        fn mutation_overhead(&self) -> u32 {
            1024
        }
    }

    pub(crate) struct ConcolicOptimisticBitwuzla {
        input: Vec<u8>,
        events: VecDeque<ConcolicEvent>,
        solver: concolic::BitwuzlaSolver,
        trace: ConcolicTrace,
        current: Option<ConcolicEvent>,
    }

    impl ConcolicOptimisticBitwuzla {
        pub(crate) fn new(input: &[u8], trace: ConcolicTrace, spec: Arc<ModuleSpec>) -> Self {
            ConcolicOptimisticBitwuzla {
                input: input.to_vec(),
                events: Self::filter_optimistic_events(&trace),
                solver: concolic::BitwuzlaSolver::new(Some(spec)),
                current: None,
                trace,
            }
        }

        fn filter_optimistic_events(context: &ConcolicTrace) -> VecDeque<ConcolicEvent> {
            if context.events.len() < 1024 {
                return context.events.iter().cloned().collect();
            }
            let mut res = VecDeque::new();
            for ids in context.events_by_location.values() {
                if ids.len() <= 32 {
                    for &i in ids {
                        res.push_back(context.events[i].clone());
                    }
                } else {
                    for &i in &ids[..16] {
                        res.push_back(context.events[i].clone());
                    }
                    for &i in &ids[ids.len() - 16..] {
                        res.push_back(context.events[i].clone());
                    }
                }
            }
            res
        }
    }

    impl QueuedInputMutation for ConcolicOptimisticBitwuzla {
        fn input(&self) -> &[u8] {
            &self.input
        }
        fn has_next(&self) -> bool {
            !self.events.is_empty()
        }
        fn next(&mut self, input: &mut [u8]) {
            let event = self.events.pop_front().unwrap();
            if self
                .solver
                .try_negate(&event, &self.trace.symvals)
                .unwrap_or(false)
            {
                self.solver.apply_model(input);
            }
            self.current = Some(event);
        }
        fn credit(&self) -> Option<String> {
            self.current
                .as_ref()
                .map(|el| format!("concolic-optimistic: {:?}", el))
        }
        fn mutation_overhead(&self) -> u32 {
            1024
        }
    }

    // TODO(strat): symbolic-like exploration? => flip and fork
    // https://github.com/trailofbits/manticore/blob/master/manticore/core/manticore.py
    /*
    pub(crate) struct BitwuzlaExploreState {
        cursor: usize,
        solve_fuel: u16,
        input: Vec<u8>,
        events: VecDeque<ConcolicEvent>,
    }

    pub(crate) struct ConcolicExploreBitwuzla {
        states: BinaryHeap<BitwuzlaExploreState>,
        solver: concolic::BitwuzlaSolver,
        context: ConcolicContext,
        current: Option<ConcolicEvent>,
    }

    impl ConcolicExploreBitwuzla {
        pub(crate) fn new(input: &[u8], context: ConcolicContext) -> Box<dyn DeterministicInputMutation> {
            Box::new(ConcolicExploreBitwuzla {
                input: input.to_vec(),
                events: context.events.iter().cloned().collect(),
                solver: concolic::BitwuzlaSolver::new(),
                current: None,
                context,
            })
        }
    }

    impl DeterministicInputMutation for ConcolicExploreBitwuzla {
        fn input(&self) -> &[u8] {
            &self.input
        }
        fn has_next(&self) -> bool {
            !self.events.is_empty()
        }
        fn next(&mut self, input: &mut [u8]) {
            let event = self.events.pop_front().unwrap();
            if self
                .solver
                .try_negate(&event, &self.context)
                .unwrap_or(false)
            {
                self.solver.apply_model(input);
            }
            let _ = self.solver.assert(&event, &self.input, &self.context);
            self.current = Some(event);
        }
        fn credit(&self) -> Option<String> {
            self.current
                .as_ref()
                .map(|el| format!("concolic-model: {:?}", el))
        }
    }
    */
}
