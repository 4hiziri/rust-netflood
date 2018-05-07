// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflood;

use netflood::netflow;

fn main() {
    println!("{:?}", netflow::field::FieldTypes::IN_BYTES);
}
