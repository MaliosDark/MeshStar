//! Small containers for the protocol tables. Every table in a node is
//! bounded (tens to a few hundred entries), so a sorted `Vec` with binary
//! search beats `BTreeMap` on code size by ~3 KB per instantiation (which
//! matters on 64 KB parts) and on memory (no per-node allocations), with
//! the same lookups.

use alloc::vec::Vec;

/// A map kept as a `Vec` sorted by key. API mirrors the subset of
/// `BTreeMap` the tables use; iteration is in key order.
#[derive(Clone, Debug)]
pub struct SmallMap<K, V> {
    items: Vec<(K, V)>,
}

impl<K: Ord, V> Default for SmallMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> SmallMap<K, V> {
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    #[inline]
    fn find(&self, k: &K) -> Result<usize, usize> {
        self.items.binary_search_by(|(key, _)| key.cmp(k))
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.find(k).is_ok()
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.find(k).ok().map(|i| &self.items[i].1)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        match self.find(k) {
            Ok(i) => Some(&mut self.items[i].1),
            Err(_) => None,
        }
    }

    /// Insert or replace; returns the previous value.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        match self.find(&k) {
            Ok(i) => Some(core::mem::replace(&mut self.items[i].1, v)),
            Err(i) => {
                self.items.insert(i, (k, v));
                None
            }
        }
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        match self.find(k) {
            Ok(i) => Some(self.items.remove(i).1),
            Err(_) => None,
        }
    }

    /// Value for `k`, inserting `V::default()` first if absent.
    pub fn get_or_default(&mut self, k: K) -> &mut V
    where
        V: Default,
    {
        let i = match self.find(&k) {
            Ok(i) => i,
            Err(i) => {
                self.items.insert(i, (k, V::default()));
                i
            }
        };
        &mut self.items[i].1
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator {
        self.items.iter().map(|(k, v)| (k, v))
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (&K, &mut V)> + ExactSizeIterator {
        self.items.iter_mut().map(|(k, v)| (&*k, v))
    }

    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> + ExactSizeIterator {
        self.items.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> + ExactSizeIterator {
        self.items.iter().map(|(_, v)| v)
    }

    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut V> + ExactSizeIterator {
        self.items.iter_mut().map(|(_, v)| v)
    }

    pub fn retain(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
        self.items.retain_mut(|(k, v)| f(k, v));
    }
}

impl<K: Ord, V> core::ops::Index<&K> for SmallMap<K, V> {
    type Output = V;
    fn index(&self, k: &K) -> &V {
        self.get(k).expect("key not in map")
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for SmallMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut m = Self::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

/// Insertion sort by key: a few hundred bytes of code instead of the
/// several KB of the standard stable sort, and the tables are tiny.
pub fn sort_by_key<T, K: Ord>(v: &mut [T], mut key: impl FnMut(&T) -> K) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && key(&v[j - 1]) > key(&v[j]) {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_basics() {
        let mut m: SmallMap<u32, &str> = SmallMap::new();
        assert!(m.insert(5, "five").is_none());
        assert!(m.insert(1, "one").is_none());
        assert_eq!(m.insert(5, "cinco"), Some("five"));
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![1, 5]);
        assert_eq!(m[&5], "cinco");
        assert_eq!(m.remove(&1), Some("one"));
        assert!(m.get(&1).is_none());
        *m.get_or_default(9) = "nine";
        assert_eq!(m.len(), 2);
        m.retain(|k, _| *k == 9);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn sort_works() {
        let mut v = vec![5, 3, 9, 1, 3];
        sort_by_key(&mut v, |x| *x);
        assert_eq!(v, vec![1, 3, 3, 5, 9]);
    }
}
