use std::sync::{Arc, RwLock};

use crossbeam_channel::{Receiver, Sender, TrySendError};

pub(crate) struct MessageBus<T: Clone + Send + Sync> {
    subscribers: RwLock<Vec<Sender<T>>>,
}

impl<T: Clone + Send + Sync> MessageBus<T> {
    pub(crate) fn new() -> Arc<Self> {
        let subscribers = RwLock::new(Vec::new());
        Arc::new(Self { subscribers })
    }

    pub(crate) fn send(&self, val: T) {
        let subs = self.subscribers.read().unwrap();
        for el in subs.iter() {
            match el.try_send(val.clone()) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(_)) => unreachable!(),
            }
        }
        // Note: We should remove subscribers that were disconnected here
    }

    pub(crate) fn subscribe(&self) -> Receiver<T> {
        let (s, r) = crossbeam_channel::unbounded();
        let mut subs = self.subscribers.write().unwrap();
        subs.push(s);
        r
    }
}
