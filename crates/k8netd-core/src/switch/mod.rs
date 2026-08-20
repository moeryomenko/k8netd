//! L2 switch seam: ethernet frame parsing and the MAC learning table
//! (spec REQ-007). Known-unicast forwarding and flooding live in `engine`
//! (plan TASK-010/011); this module only owns the parser and the table.

pub mod frame;
pub mod mac_table;
