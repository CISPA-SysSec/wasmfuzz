use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

use crossbeam_channel::{Receiver, Sender, TrySendError};

pub(crate) struct MessageBus<T: Clone + Send + Sync> {
    subscribers: RwLock<Vec<Sender<T>>>,
    flag_stale: AtomicBool,
}

impl<T: Clone + Send + Sync> MessageBus<T> {
    pub(crate) fn new() -> Arc<Self> {
        let subscribers = RwLock::new(Vec::new());
        let flag_stale = AtomicBool::new(false);
        Arc::new(Self {
            subscribers,
            flag_stale,
        })
    }

    fn send_and_remove_disconnected(&self, val: T) {
        let mut subs = self.subscribers.write().unwrap();
        subs.retain(|el| match el.try_send(val.clone()) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(_)) => false,
            Err(TrySendError::Full(_)) => unreachable!(),
        });
        self.flag_stale.store(false, Ordering::SeqCst);
    }

    pub(crate) fn send(&self, val: T) {
        if self.flag_stale.load(Ordering::Relaxed) {
            return self.send_and_remove_disconnected(val);
        }

        let subs = self.subscribers.read().unwrap();
        for el in subs.iter() {
            match el.try_send(val.clone()) {
                Ok(()) => {}
                Err(TrySendError::Disconnected(_)) => {
                    self.flag_stale.store(true, Ordering::SeqCst);
                }
                Err(TrySendError::Full(_)) => unreachable!(),
            }
        }
    }

    pub(crate) fn subscribe(&self) -> Receiver<T> {
        let (s, r) = crossbeam_channel::unbounded();
        let mut subs = self.subscribers.write().unwrap();
        subs.push(s);
        r
    }
}
