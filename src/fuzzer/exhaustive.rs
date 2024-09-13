use rand::{seq::SliceRandom, Rng};

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
