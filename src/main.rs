// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflood;
extern crate netflow;
extern crate rand;
extern crate serde_json;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate clap;

use clap::{App, ArgMatches};

use netflood::flow_generator::{from_option, from_template};
use netflood::json_dump;
use netflood::template_parser::{extract_option, extract_template};
use netflow::flowset::{DataFlow, DataTemplate, FlowSet, OptionTemplate};

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
    let mut datas = Vec::new();
    let options = options.iter().map(|opt| &opt.templates);

    for opt in options {
        datas.append(&mut from_option(&opt, count));
    }

    datas
}

fn cmd_generate(matches: &ArgMatches) {
    let default_count = 3; // TODO: set flow count
    let count = default_count;
    let mut flowsets: Vec<FlowSet> = Vec::new();

    if let Some(template_file) = matches.value_of("template") {
        if let Some(template) = get_template(template_file) {
            debug!("template: {:?}", template);

            let dataflows = take_temp(count, &template);
            flowsets.push(FlowSet::from(template));

            for flow in dataflows {
                flowsets.push(FlowSet::from(flow));
            }
        }
    }

    if let Some(option_file) = matches.value_of("option") {
        if let Some(options) = get_option(option_file) {
            debug!("options: {:?}", options);

            let dataflows = take_opt(count, &options);
            for option in options {
                flowsets.push(FlowSet::from(option));
            }

            for flow in dataflows {
                flowsets.push(FlowSet::from(flow));
            }
        }
    }

    debug!("FlowSets: {:?}", flowsets);
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

    // let template_name = "./rsc/template/template.json";
    // let mut bufr = BufReader::new(File::open(filename).unwrap());
    // let _tmps = template_parser::from_reader(&mut bufr);
    // let flows = pcap_analysis::dump_netflow("./rsc/netflows.pcapng", 2055);
    // println!("Flowsets num: {}", flows.len());
}
