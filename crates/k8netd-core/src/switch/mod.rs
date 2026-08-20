//! L2 switch seam: ethernet frame parsing, the MAC learning table, the
//! forwarding/flooding engine, and the gateway function (spec REQ-007). The
//! engine contract is test-first (plan TASK-010); TASK-011 implements it in
//! `engine`. The gateway contract is test-first (plan TASK-012); TASK-013
//! implements it in `gateway`.

pub mod engine;
pub mod frame;
pub mod gateway;
pub mod mac_table;
