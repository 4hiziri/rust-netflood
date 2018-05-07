// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflow;
extern crate serde_json;

use std::io::BufReader;
use std::fs::File;

fn main() {
    let bufr = BufReader::new(
        File::open(
            "/home/tkgsy/misc/scripts/netflood/netflood/template/template.json",
        ).unwrap(),
    );

    // let mut template = String::new();
    // bufr.read_to_string(&mut template).unwrap();

    let val: serde_json::Value = serde_json::from_reader(bufr).unwrap();

    println!("{:?}", val);

    println!("{:?}", netflow::field::FieldTypes::DST_AS);
}
