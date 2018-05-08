// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflow;
extern crate serde_json;
extern crate netflood;

use std::io::BufReader;
use std::fs::File;

use netflood::template_parser;

fn main() {
    let bufr = BufReader::new(
        File::open(
            "/home/tkgsy/misc/scripts/netflood/netflood/rsc/template/template.json",
        ).unwrap(),
    );

    let val: serde_json::Value = serde_json::from_reader(bufr).unwrap();

    println!("{:?}", val);

    println!(
        "{:?}",
        template_parser::from_str("{\"name\": \"John Doe\"}")
    );
}
