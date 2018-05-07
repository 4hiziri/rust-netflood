use netflow::field::{Field, Option};
use std::boxed::Box;

#[derive(Debug, Clone)]
struct DataTemplate {
    flowset_id: u16,
    length: u16,
    template_id: u16,
    field_count: u16,
    fields: Vec<Field>,
}

#[derive(Debug, Clone)]
struct OptionTemplate {
    flowset_id: u16,
    length: u16,
    template_id: u16,
    option_scope_length: u16,
    option_length: u16,
    options: Vec<Option>,
}

#[derive(Debug, Clone)]
struct DataFlow {
    flowset_id: u16,
    length: u16,
    records: Vec<u16>,
}

pub trait FlowSet {}

pub struct Netflow9 {
    version: u16,
    count: u16,
    sys_up_time: u32,
    timestamp: u32,
    flow_sequence: u32,
    flowset_id: u32,
    flow_sets: Vec<Box<FlowSet>>,
}
