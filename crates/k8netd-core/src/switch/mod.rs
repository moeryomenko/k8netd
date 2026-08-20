//! L2 switch seam: ethernet frame parsing, the MAC learning table, and the
//! forwarding/flooding engine (spec REQ-007). The engine contract is
//! test-first (plan TASK-010); TASK-011 implements it in `engine`.

pub mod engine;
pub mod frame;
pub mod mac_table;
