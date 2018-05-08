// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflow;
extern crate serde_json;
extern crate netflood;

use std::io::BufReader;
use std::fs::File;

use netflood::template_parser;
use netflood::pcap_analysis;

fn main() {
    let mut bufr = BufReader::new(
        File::open(
            "/home/tkgsy/misc/scripts/netflood/netflood/rsc/template/template.json",
        ).unwrap(),
    );

    println!("{:?}", template_parser::from_reader(&mut bufr));
    pcap_analysis::dump_data_template(
        "/home/tkgsy/misc/scripts/netflood/netflood/rsc/netflows.pcapng",
        2055,
    );
}
