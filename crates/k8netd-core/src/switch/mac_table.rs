//! MAC learning table for the L2 switch (spec REQ-007, plan TASK-008, TEST-FIRST).
//!
//! TASK-008 (test-first): the `tests` module below defines the contract for
//! the MAC table. The table does not exist yet, so the tests fail to compile
//! (red phase). TASK-009 implements the table in this file to make the tests
//! pass; the tests module stays at the bottom of the file per Rust convention.

use std::collections::HashMap;
use std::fmt;

use crate::model::MacAddr;

/// An opaque port handle identifying a switch port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortId(pub u32);

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port {}", self.0)
    }
}

/// A MAC learning table with recency-based (LRU) eviction.
///
/// Aging is recency-based, not wall-clock: re-learning an existing MAC
/// refreshes its recency, and when the table is at capacity learning a new
/// MAC evicts the least-recently-used entry. The table never grows beyond
/// `capacity`, stores whatever MAC it is given (including the zero MAC), and
/// learning into a zero-capacity table is a silent no-op.
#[derive(Debug)]
pub struct MacTable {
    capacity: usize,
    clock: u64,
    entries: HashMap<MacAddr, Entry>,
}

/// A table entry: the learned port and its recency stamp.
#[derive(Debug, Clone, Copy)]
struct Entry {
    port: PortId,
    last_seen: u64,
}

impl MacTable {
    /// Creates an empty table that holds at most `capacity` entries.
    pub fn new(capacity: usize) -> MacTable {
        MacTable {
            capacity,
            clock: 0,
            entries: HashMap::new(),
        }
    }

    /// Learns or refreshes the mapping from `mac` to `port`.
    ///
    /// Re-learning an existing MAC updates its port and refreshes its
    /// recency. When the table is at capacity, the least-recently-used entry
    /// is evicted. Learning into a zero-capacity table is a silent no-op.
    pub fn learn(&mut self, port: PortId, mac: MacAddr) {
        if self.capacity == 0 {
            return;
        }
        self.clock = self.clock.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(&mac) {
            entry.port = port;
            entry.last_seen = self.clock;
            return;
        }
        if self.entries.len() == self.capacity {
            let lru = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(mac, _)| *mac);
            if let Some(lru) = lru {
                self.entries.remove(&lru);
            }
        }
        self.entries.insert(
            mac,
            Entry {
                port,
                last_seen: self.clock,
            },
        );
    }

    /// Returns the port that `mac` was last learned on, if any.
    pub fn lookup(&self, mac: MacAddr) -> Option<PortId> {
        self.entries.get(&mac).map(|entry| entry.port)
    }

    /// Removes the entry for `mac`; returns true when an entry existed.
    pub fn evict(&mut self, mac: MacAddr) -> bool {
        self.entries.remove(&mac).is_some()
    }

    /// Returns the number of learned entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no MAC has been learned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-009 to satisfy these tests:
    //
    // pub struct PortId(pub u32); // opaque port handle
    //
    // pub struct MacTable { ... }
    //
    // impl MacTable {
    //     pub fn new(capacity: usize) -> MacTable
    //     pub fn learn(&mut self, port: PortId, mac: MacAddr) // insert or refresh
    //     pub fn lookup(&self, mac: MacAddr) -> Option<PortId>
    //     pub fn evict(&mut self, mac: MacAddr) -> bool // true if the entry existed
    //     pub fn len(&self) -> usize
    //     pub fn is_empty(&self) -> bool
    // }
    //
    // Aging pin (decided here): aging is recency-based (LRU), not wall-clock.
    // The switch is synchronous with no timers and REQ-007 defines no aging
    // interval, so "aging" means: re-learning an existing MAC refreshes its
    // recency (the entry becomes the most recent and is evicted last); when
    // the table is at capacity, learning a new MAC evicts the
    // least-recently-used entry. The table never grows beyond `capacity`.
    //
    // Policy pins (decided here): the table stores whatever MAC it is given —
    // including the zero MAC 00:00:00:00:00:00 — and never validates MACs.
    // Dropping pathological source MACs is the forwarding engine's concern
    // (TASK-010/011). Learning into a zero-capacity table is a silent no-op.

    use super::*;
    use crate::model::MacAddr;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    // REQ-2: learning from source MACs.

    #[test]
    fn learn_then_lookup_returns_port() {
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), Some(PortId(1)));
    }

    #[test]
    fn learn_multiple_macs_per_port() {
        // The table maps MAC -> port; one port may legitimately own several MACs.
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.learn(PortId(1), mac("02:00:00:00:00:02"));
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), Some(PortId(1)));
        assert_eq!(table.lookup(mac("02:00:00:00:00:02")), Some(PortId(1)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn learn_same_mac_new_port_updates_mapping() {
        // A MAC that moves to another port is re-learned to the new port.
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.learn(PortId(2), mac("02:00:00:00:00:01"));
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), Some(PortId(2)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn relearn_same_mac_same_port_keeps_len() {
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn learn_zero_mac_is_stored() {
        // Policy pin: the table stores the zero MAC; dropping it is the
        // engine's call, not the table's.
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("00:00:00:00:00:00"));
        assert_eq!(table.lookup(mac("00:00:00:00:00:00")), Some(PortId(1)));
    }

    #[test]
    fn new_table_is_empty() {
        let table = MacTable::new(16);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    // REQ-3: lookup.

    #[test]
    fn lookup_absent_mac_returns_none() {
        let table = MacTable::new(16);
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), None);
    }

    #[test]
    fn lookup_after_evict_returns_none() {
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.evict(mac("02:00:00:00:00:01"));
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), None);
    }

    // REQ-4: eviction and aging behavior.

    #[test]
    fn evict_removes_entry() {
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        assert!(table.evict(mac("02:00:00:00:00:01")));
        assert!(table.is_empty());
    }

    #[test]
    fn evict_absent_mac_returns_false() {
        let mut table = MacTable::new(16);
        assert!(!table.evict(mac("02:00:00:00:00:01")));
    }

    #[test]
    fn evict_then_relearn_works() {
        let mut table = MacTable::new(16);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.evict(mac("02:00:00:00:00:01"));
        table.learn(PortId(2), mac("02:00:00:00:00:01"));
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), Some(PortId(2)));
    }

    #[test]
    fn capacity_full_evicts_oldest() {
        let mut table = MacTable::new(2);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.learn(PortId(2), mac("02:00:00:00:00:02"));
        table.learn(PortId(3), mac("02:00:00:00:00:03"));
        // The oldest entry (A) is evicted; B and C remain; len never exceeds capacity.
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), None);
        assert_eq!(table.lookup(mac("02:00:00:00:00:02")), Some(PortId(2)));
        assert_eq!(table.lookup(mac("02:00:00:00:00:03")), Some(PortId(3)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn relearn_refreshes_recency() {
        // Aging pin: re-learn refreshes recency, so the re-learned entry is
        // evicted last. A learned, B learned, A re-learned => B is LRU.
        let mut table = MacTable::new(2);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        table.learn(PortId(2), mac("02:00:00:00:00:02"));
        table.learn(PortId(1), mac("02:00:00:00:00:01")); // refresh A
        table.learn(PortId(3), mac("02:00:00:00:00:03")); // evicts B, not A
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), Some(PortId(1)));
        assert_eq!(table.lookup(mac("02:00:00:00:00:02")), None);
        assert_eq!(table.lookup(mac("02:00:00:00:00:03")), Some(PortId(3)));
    }

    #[test]
    fn zero_capacity_table_drops_all_learns() {
        let mut table = MacTable::new(0);
        table.learn(PortId(1), mac("02:00:00:00:00:01"));
        assert!(table.is_empty());
        assert_eq!(table.lookup(mac("02:00:00:00:00:01")), None);
    }
}
