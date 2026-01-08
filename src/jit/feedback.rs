use crate::fuzzer::i2s_patches::CmpLog;
use crate::{HashMap, HashSet};

use crate::ir::Location;

// TODO: move this to instrumentation passes?

pub(crate) struct FeedbackContext {
    pub(crate) cmplog: HashMap<Location, HashSet<CmpLog>>, // not modified directly
    pub stdout: Vec<u8>,
}

impl FeedbackContext {
    pub(crate) fn new() -> Self {
        Self {
            cmplog: HashMap::default(),
            stdout: Vec::new(),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.cmplog.clear();
        self.stdout.clear();
    }
}
