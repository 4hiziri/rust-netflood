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

use clap::App;

use netflood::flow_generator;
use netflood::json_dump;
use netflood::template_parser::{extract_option, extract_template};

// Need cmd
// + extract template from pcap
// + send netflow by json, xml or something

fn cmd_generate(matches: &clap::ArgMatches) {
    let default_count = 3; // TODO: set flow count
    let flow_count = default_count;
    let mut dataflow = Vec::new();

    let templates = if let Some(template) = matches.value_of("template") {
        Some(json_dump::json_template(template))
    } else {
        None
    };

    if let Some(templates) = templates {
        debug!("template: {:?}", templates);

        for template in templates {
            dataflow.append(&mut flow_generator::from_template(template, flow_count));
        }
    }

    let options = if let Some(option) = matches.value_of("option") {
        Some(json_dump::json_option(option))
    } else {
        None
    };

    if let Some(options) = options {
        debug!("option: {:?}", options);

        for option in options {
            dataflow.append(&mut flow_generator::from_option(option, flow_count));
        }
    }

    debug!("DataFlow: {:?}", dataflow);
}

fn cmd_extract(matches: &clap::ArgMatches) {
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
