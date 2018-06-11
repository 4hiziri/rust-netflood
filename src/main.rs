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

use netflow::flowset::{DataTemplate, DataTemplateItem, FlowSet};
use netflow::netflow::NetFlow9;

use netflood::pcap_analysis;
use netflood::template_parser;

// Need cmd
// + extract template from pcap
// + send netflow by json, xml or something

// TODO: divide Template and Option?
// Return Data Template or Option Template
fn extract_template(filename: &str) -> Vec<DataTemplateItem> {
    let netflow_packets: Vec<Vec<u8>> = pcap_analysis::dump_netflow(filename, 2055);
    let template_flows: Vec<DataTemplateItem> = netflow_packets
        .into_iter()
        .map(|packets| NetFlow9::from_bytes(&packets).unwrap())
        .fold(Vec::new(), |mut acc_flowsets, netflow| {
            acc_flowsets.append(&mut netflow.flow_sets.into_iter().fold(
                Vec::new(),
                |mut acc, set| match set {
                    FlowSet::DataTemplate(temp) => {
                        acc.push(temp);
                        acc
                    }
                    _ => acc,
                },
            ));

            acc_flowsets
        })
        .into_iter()
        .fold(Vec::new(), |mut acc, mut data_template| {
            acc.append(data_template.templates.as_mut());
            acc
        })
        .into_iter()
        .fold(Vec::new(), |mut acc, item| {
            let is_contained = {
                let acc = &acc;
                acc.into_iter().fold(false, |is_contained, i| {
                    is_contained || i.template_id == item.template_id
                })
            };

            if is_contained {
                acc
            } else {
                acc.push(item);
                acc
            }
        });

    template_flows // .collect()
}

fn main() {
    env_logger::init();

    let template_name = "./rsc/template/template.json";
    let pcap_file = "./rsc/netflows.pcapng";

    // let mut bufr = BufReader::new(File::open(filename).unwrap());
    // let _tmps = template_parser::from_reader(&mut bufr);
    // let flows = pcap_analysis::dump_netflow("./rsc/netflows.pcapng", 2055);
    // println!("Flowsets num: {}", flows.len());

    let netflows = extract_template(pcap_file);
    println!("len: {:?}", netflows.len());
    println!("netflows: {:?}", netflows[0]);

    for flow in netflows {
        println!("Template ID: {}", flow.template_id);
    }

    // let netflow9: Vec<NetFlow9> = flows
    //     .into_iter()
    //     .map(|flow| NetFlow9::from_bytes(&flow).unwrap())
    //     .collect();

    // println!("flows num: {}", netflow9.len());
    // println!("flow: {:?}", netflow9[16].flow_sets[0]);
}
