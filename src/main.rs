// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflood;
extern crate netflow;
extern crate serde_json;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;

use std::fs::File;
use std::io::BufReader;
use netflow::flowset::{DataTemplate, DataTemplateItem, FlowSet, OptionTemplateItem};
use netflow::netflow::NetFlow9;

use netflood::json_dump;
use netflood::pcap_analysis;
use netflood::template_parser;

// Need cmd
// + extract template from pcap
// + send netflow by json, xml or something

fn is_contained_template(vec: &Vec<DataTemplateItem>, item: &DataTemplateItem) -> bool {
    vec.into_iter().fold(false, |is_contained, i| {
        is_contained || i.template_id == item.template_id
    })
}

fn is_contained_option(vec: &Vec<OptionTemplateItem>, item: &OptionTemplateItem) -> bool {
    vec.into_iter().fold(false, |is_contained, i| {
        is_contained || i.template_id == item.template_id
    })
}

// Return DataTemplateItem for extract and dump template
fn extract_template(filename: &str) -> Vec<DataTemplateItem> {
    let templates = pcap_analysis::dump_netflow(filename, 2055)
        .into_iter()
        .map(|packets| NetFlow9::from_bytes(&packets).unwrap())
        .flat_map(|netflow| {
            netflow
                .flow_sets
                .into_iter()
                .map(|set| match set {
                    FlowSet::DataTemplate(temp) => Some(temp),
                    _ => None,
                })
                .filter(|opt| opt.is_some())
                .map(|some| some.unwrap())
        })
        .flat_map(|data_temp| data_temp.templates);

    // remove duplicates
    templates.into_iter().fold(Vec::new(), |mut acc, item| {
        if is_contained_template(&acc, &item) {
            acc
        } else {
            acc.push(item);
            acc
        }
    })
}

fn extract_option(filename: &str) -> Vec<OptionTemplateItem> {
    let templates = pcap_analysis::dump_netflow(filename, 2055)
        .into_iter()
        .map(|packets| NetFlow9::from_bytes(&packets).unwrap())
        .flat_map(|netflow| {
            netflow
                .flow_sets
                .into_iter()
                .map(|set| match set {
                    FlowSet::OptionTemplate(temp) => Some(temp),
                    _ => None,
                })
                .filter(|opt| opt.is_some())
                .map(|some| some.unwrap())
        })
        .map(|data_temp| data_temp.templates);
>>>>>>> a4778217bb34a507826c82f95b31e514e1e29483

    // remove duplicates
    templates.into_iter().fold(Vec::new(), |mut acc, item| {
        if is_contained_option(&acc, &item) {
            acc
        } else {
            acc.push(item);
            acc
        }
    })
}

// TODO: add arguments parser
fn main() {
    env_logger::init();

    let template_name = "./rsc/template/template.json";
    let pcap_file = "./rsc/netflows.pcapng";

    // let mut bufr = BufReader::new(File::open(filename).unwrap());
    // let _tmps = template_parser::from_reader(&mut bufr);
    // let flows = pcap_analysis::dump_netflow("./rsc/netflows.pcapng", 2055);
    // println!("Flowsets num: {}", flows.len());

    let templates = extract_template(pcap_file);
    println!("len: {:?}", templates.len());
    println!("netflows: {:?}", templates[0]);

    for temp in &templates {
        println!("Template ID: {}", temp.template_id);
    }

    let options = extract_option(pcap_file);
    println!("len: {:?}", options.len());
    println!("netflows: {:?}", options[0]);

    for opt in &options {
        println!("Template ID: {}", opt.template_id);
    }

    println!("json test");
    json_dump::dump_template(&templates[0]);
}
