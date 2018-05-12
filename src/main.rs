// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflow;
extern crate serde_json;
extern crate netflood;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::io::BufReader;
use std::fs::File;

use netflood::template_parser;
use netflood::pcap_analysis;

use netflow::flowset::NetFlow9;

fn main() {
    env_logger::init();

    let mut bufr = BufReader::new(File::open("./rsc/template/template.json").unwrap());

    let tmps = template_parser::from_reader(&mut bufr);

    let flows = pcap_analysis::dump_data_template("./rsc/netflows.pcapng", 2055);
    println!("Flowsets num: {}", flows.len());

    for flow in flows {
        let netflow = NetFlow9::new(&flow).unwrap();
        println!("NetFlow9: {:?}", netflow);
    }

    // let netflow9: Vec<NetFlow9> = flows
    //     .into_iter()
    //     .map(|flow| NetFlow9::new(&flow).unwrap())
    //     .collect();

    // println!("netflow9: {:?}", netflow9);
}
