// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflow;
extern crate serde_json;
extern crate netflood;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;

use std::io::BufReader;
use std::fs::File;

use netflood::template_parser;
use netflood::pcap_analysis;

use netflow::netflow::NetFlow9;

fn main() {
    env_logger::init();

    let mut bufr = BufReader::new(File::open("./rsc/template/template.json").unwrap());

    let _tmps = template_parser::from_reader(&mut bufr);

    let flows = pcap_analysis::dump_data_template("./rsc/netflows.pcapng", 2055);
    println!("Flowsets num: {}", flows.len());

    let netflow9: Vec<NetFlow9> = flows
        .into_iter()
        .map(|flow| NetFlow9::from_bytes(&flow).unwrap())
        .collect();

    println!("flows num: {}", netflow9.len());
    println!("flow: {:?}", netflow9[16].flow_sets[0]);
}
