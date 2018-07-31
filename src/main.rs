// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflood;
extern crate netflow;
extern crate rand;
extern crate serde_json;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate clap;
extern crate time;

use clap::{App, ArgMatches};

use netflood::flow_generator::{from_option, from_template};
use netflood::json_dump;
use netflood::sender;
use netflood::template_parser::{extract_option, extract_template};
use netflow::flowset::{DataFlow, DataTemplate, FlowSet, OptionTemplate};
use netflow::netflow::NetFlow9;

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// Need cmd
// + send netflow by json, xml or something

fn get_template(template_file: &str) -> Option<DataTemplate> {
    let temp_items = json_dump::json_template(template_file);

    if temp_items.len() == 0 {
        None
    } else {
        Some(DataTemplate::new(temp_items)) // delete dup
    }
}

fn take_temp(count: usize, template: &DataTemplate) -> Vec<DataFlow> {
    let mut dataflows = Vec::new();

    for temp in &template.templates {
        dataflows.append(&mut from_template(temp, count));
    }

    dataflows
}

// FIXME: option is one at system?
fn get_option(option_file: &str) -> Option<Vec<OptionTemplate>> {
    let options = json_dump::json_option(option_file);

    if options.len() == 0 {
        None
    } else {
        Some(
            options
                .into_iter()
                .map(|option| OptionTemplate::new(option))
                .collect(),
        )
    }
}

fn take_opt(count: usize, options: &Vec<OptionTemplate>) -> Vec<DataFlow> {
    let mut dataflows = Vec::new();
    let options = options.iter().map(|opt| &opt.templates);

    for opt in options {
        dataflows.append(&mut from_option(&opt, count));
    }

    dataflows
}

fn generate_from_data_template(matches: &ArgMatches, count: usize) -> (Vec<FlowSet>, Vec<FlowSet>) {
    let mut flowsets: Vec<FlowSet> = Vec::new();
    let mut templates: Vec<FlowSet> = Vec::new();

    matches.value_of("template").map(|template_file| {
        get_template(template_file).map(|template| {
            debug!("template: {:?}", template);

            for flow in take_temp(count, &template) {
                flowsets.push(FlowSet::from(flow));
            }

            templates.push(FlowSet::from(template));
        })
    });

    (flowsets, templates)
}

fn generate_from_option_template(
    matches: &ArgMatches,
    count: usize,
) -> (Vec<FlowSet>, Vec<FlowSet>) {
    let mut flowsets: Vec<FlowSet> = Vec::new();
    let mut templates: Vec<FlowSet> = Vec::new();

    matches.value_of("option").map(|option_file| {
        get_option(option_file).map(|options| {
            debug!("options: {:?}", options);

            for flow in take_opt(count, &options) {
                flowsets.push(FlowSet::from(flow));
            }

            for option in options {
                templates.push(FlowSet::from(option));
            }
        })
    });

    (flowsets, templates)
}

// TODO: design arguments and set data
fn cmd_generate(matches: &ArgMatches) {
    let count = matches
        .value_of("count")
        .unwrap()
        .parse::<usize>()
        .expect("Error while parsing count");
    let dst_addr = IpAddr::from_str(matches.value_of("dst-addr").unwrap())
        .expect("Error while parse dst-addr!");
    let seq_num = matches
        .value_of("seq-num")
        .unwrap()
        .parse::<u32>()
        .expect("Error: invalid sequence number, -s");
    let id = matches
        .value_of("id")
        .unwrap()
        .parse::<u32>()
        .expect("Error: invalid id, -i");
    let (mut flowsets, mut templates) = generate_from_data_template(&matches, count);
    let (mut opt_flows, mut opt_temps) = generate_from_option_template(&matches, count);
    flowsets.append(&mut opt_flows);
    templates.append(&mut opt_temps);

    debug!("Templates count: {:?}", templates.len());
    debug!("FlowSets count: {:?}", flowsets.len());

    let id = id;
    let seq_num = seq_num;
    let dst_port = matches
        .value_of("port")
        .unwrap()
        .parse::<u16>()
        .expect("Invalid port");

    // FIXME: Error at length of template flowsetexit
    let flow1 = NetFlow9::new(
        100000,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
        seq_num,
        id,
        templates,
    );
    let flow2 = NetFlow9::new(
        100000,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
        seq_num + 1,
        id,
        flowsets,
    );

    // debug!("Template Flow:\n{:?}", &flow1);
    // debug!("Data Flow:\n{:?}", &flow2);
    for flowset in &flow1.flow_sets {
        match flowset {
            FlowSet::OptionTemplate(option) => {
                debug!("Option Dump:\n{:?}", option);
                debug!("Option bytes:\n{:?}", option.to_bytes());
            }
            _ => (),
        }
    }

    sender::send_netflow(&vec![flow1, flow2], dst_addr, dst_port);
    // println!("{}", seq_num + 1);
}

fn cmd_extract(matches: &ArgMatches) {
    // TODO: add human-readable format
    match matches.subcommand() {
        ("template", Some(matches)) => {
            debug!("extract template");

            let pcap = matches.value_of("PCAP").unwrap();
            let templates = extract_template(pcap);

            debug!("len: {:?}", templates.len());
            debug!("netflows: {:?}", templates[0]);

            let temp_json = json_dump::dump_template(&templates).unwrap();

            println!("{}", &temp_json);
        }
        ("option", Some(matches)) => {
            debug!("extract option");

            let pcap = matches.value_of("PCAP").unwrap();
            let options = extract_option(pcap);

            debug!("len: {:?}", options.len());
            debug!("netflows: {:?}", options[0]);

            let opt_json = json_dump::dump_option(&options).unwrap();
            println!("{}", &opt_json);
        }
        _ => {
            println!("ERROR! sorry I forgot implementing.");
        }
    }
}

fn main() {
    env_logger::init();

    let yaml = load_yaml!("opt.yml");
    let matches = App::from_yaml(yaml)
        .name(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!())
        .get_matches();

    match matches.subcommand() {
        ("extract", Some(matches)) => {
            debug!("extract cmd");

            cmd_extract(matches);
        }
        ("generate", Some(matches)) => {
            debug!("generate cmd");

            cmd_generate(matches);
        }
        _ => println!("{}", matches.usage()),
    }
}
