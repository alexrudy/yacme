use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

use crate::Container;

pub(crate) trait Cacheable<S>: Clone {
    type Key: Debug + Eq + Hash;
    type Value: Debug + Clone;
    fn key(&self) -> Self::Key;
    fn container(&self) -> Container<Self::Value, S>;
}

#[derive(Debug, Clone)]
pub(crate) struct CacheMap<T: Cacheable<S>, S>(HashMap<T::Key, Container<T::Value, S>>);

impl<T: Cacheable<S>, S> Default for CacheMap<T, S> {
    fn default() -> Self {
        CacheMap(HashMap::default())
    }
}

impl<T, S> CacheMap<T, S>
where
    T: Cacheable<S>,
{
    pub(crate) fn insert(&mut self, item: T) {
        match self.0.entry(item.key()) {
            Entry::Occupied(entry) => {
                let new_value = item.container().schema().deref().deref().clone();
                entry.get().store(new_value)
            }
            Entry::Vacant(entry) => {
                entry.insert(item.container());
            }
        };
    }
}

impl<T, S> Deref for CacheMap<T, S>
where
    T: Cacheable<S>,
{
    type Target = HashMap<T::Key, Container<T::Value, S>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, S> DerefMut for CacheMap<T, S>
where
    T: Cacheable<S>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub(crate) struct Cache<T, S>(Mutex<CacheMap<T, S>>)
where
    T: Cacheable<S>;

impl<T: Cacheable<S>, S> Default for Cache<T, S> {
    fn default() -> Self {
        Cache(Mutex::default())
    }
}

impl<T, S> Cache<T, S>
where
    T: Cacheable<S>,
{
    pub(crate) fn insert(&self, value: T) {
        let mut inner = self.0.lock().unwrap();
        inner.insert(value);
    }

    pub(crate) fn inner(&self) -> MutexGuard<'_, CacheMap<T, S>> {
        self.0.lock().unwrap()
    }

    pub(crate) fn get(&self, key: &T::Key) -> Option<Container<T::Value, S>> {
        let inner = self.0.lock().unwrap();
        inner.get(key).cloned()
    }
}
