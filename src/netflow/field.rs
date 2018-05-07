#[derive(Debug, Clone, Copy)]
pub struct FieldType(u16);
#[derive(Debug, Clone, Copy)]
pub struct OptionType(u16);

#[allow(non_snake_case)]
pub mod FieldTypes {
    use super::FieldType;

    pub const IN_BYTES: FieldType = FieldType(1);
    pub const IN_PKTS: FieldType = FieldType(2);
    pub const FLOWS: FieldType = FieldType(3);
    pub const PROTOCOL: FieldType = FieldType(4);
    pub const TOS: FieldType = FieldType(5);
    pub const TCP_FLAGS: FieldType = FieldType(6);
    pub const IPV4_SRC_ADDR: FieldType = FieldType(8);
    pub const SRC_MASK: FieldType = FieldType(9);
    pub const INPUT_SNMP: FieldType = FieldType(10);
    pub const IPV4_DST_ADDR: FieldType = FieldType(12);
    pub const DST_MASK: FieldType = FieldType(13);
    pub const OUTPUT_SNMP: FieldType = FieldType(14);
    pub const IPV4_NEXT_HOP: FieldType = FieldType(15);
    pub const SRC_AS: FieldType = FieldType(16);
    pub const DST_AS: FieldType = FieldType(17);
    pub const BGP_IPV4_NEXT_HOP: FieldType = FieldType(18);
    pub const MUL_DST_PKTS: FieldType = FieldType(19);
    pub const MUL_DST_BYTES: FieldType = FieldType(20);
    pub const LAST_SWITCHED: FieldType = FieldType(21);
    pub const FIRST_SWITCHED: FieldType = FieldType(22);
    pub const OUT_BYTES: FieldType = FieldType(23);
    pub const OUT_PKTS: FieldType = FieldType(24);
    pub const IPV6_SRC_ADDR: FieldType = FieldType(27);
    pub const IPV6_DST_ADDR: FieldType = FieldType(28);
    pub const IPV6_SRC_MASK: FieldType = FieldType(29);
    pub const IPV6_DST_MASK: FieldType = FieldType(30);
    pub const IPV6_FLOW_LABEL: FieldType = FieldType(31);
    pub const ICMP_TYPE: FieldType = FieldType(32);
    pub const MUL_IGMP_TYPE: FieldType = FieldType(33);
    pub const SAMPLING_INTERVAL: FieldType = FieldType(34);
    pub const SAMPLING_ALGORITHM: FieldType = FieldType(35);
    pub const FLOW_ACTIVE_TIMEOUT: FieldType = FieldType(36);
    pub const FLOW_INACTIVE_TIMEOUT: FieldType = FieldType(37);
    pub const ENGINE_TYPE: FieldType = FieldType(38);
    pub const ENGINE_ID: FieldType = FieldType(39);
    pub const TOTAL_BYTES_EXP: FieldType = FieldType(40);
    pub const TOTAL_PKTS_EXP: FieldType = FieldType(41);
    pub const TOTAL_FLOWS_EXP: FieldType = FieldType(42);
    pub const MPLS_TOP_LABEL_TYPE: FieldType = FieldType(46);
    pub const MPLS_TOP_LABEL_IP_ADDR: FieldType = FieldType(47);
    pub const FLOW_SAMPLER_ID: FieldType = FieldType(48);
    pub const FLOW_SAMPLER_MODE: FieldType = FieldType(49);
    pub const FLOW_SAMPLER_RANDOM_INTERVAL: FieldType = FieldType(50);
    pub const DST_TOS: FieldType = FieldType(55);
    pub const SRC_MAC: FieldType = FieldType(56);
    pub const DST_MAC: FieldType = FieldType(57);
    pub const SRC_VLAN: FieldType = FieldType(58);
    pub const DST_VLAN: FieldType = FieldType(59);
    pub const IP_PROTOCOL_VERSION: FieldType = FieldType(60);
    pub const DIRECTION: FieldType = FieldType(61);
    pub const IPV6_NEXT_HOP: FieldType = FieldType(62);
    pub const BGP_IPV6_NEXT_HOP: FieldType = FieldType(63);
    pub const IPV6_OPTION_HEADERS: FieldType = FieldType(64);
    pub const MPLS_LABEL_1: FieldType = FieldType(70);
    pub const MPLS_LABEL_2: FieldType = FieldType(71);
    pub const MPLS_LABEL_3: FieldType = FieldType(72);
    pub const MPLS_LABEL_4: FieldType = FieldType(73);
    pub const MPLS_LABEL_5: FieldType = FieldType(74);
    pub const MPLS_LABEL_6: FieldType = FieldType(75);
    pub const MPLS_LABEL_7: FieldType = FieldType(76);
    pub const MPLS_LABEL_8: FieldType = FieldType(77);
    pub const MPLS_LABEL_9: FieldType = FieldType(78);
    pub const MPLS_LABEL_10: FieldType = FieldType(79);
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod OptionTypes {
    use super::OptionType;

    pub const System: OptionType = OptionType(1);
    pub const Interface: OptionType = OptionType(2);
    pub const Line_Card: OptionType = OptionType(3);
    pub const NetFlow_Cache: OptionType = OptionType(4);
    pub const Template: OptionType = OptionType(5);
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    field_type: FieldType,
    length: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Option {
    option_type: OptionType,
    length: u16,
}
