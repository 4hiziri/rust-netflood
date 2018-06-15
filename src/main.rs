// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
extern crate netflood;
extern crate netflow;
extern crate serde_json;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate clap;

use clap::App;

use netflow::flowset::{DataTemplateItem, FlowSet, OptionTemplateItem};
use netflow::netflow::NetFlow9;

use netflood::json_dump;
use netflood::pcap_analysis;

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

fn extract_cmd(matches: &clap::ArgMatches) {
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
    let app = App::from_yaml(yaml)
        .name(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!());

    match app.get_matches().subcommand() {
        ("extract", Some(matches)) => {
            debug!("extract cmd");

            extract_cmd(matches);
        }
        ("generate", Some(_matches)) => {
            debug!("generate cmd");
        }
        _ => {
            debug!("not specified"); // show help?
        }
    }

    // let template_name = "./rsc/template/template.json";
    // let mut bufr = BufReader::new(File::open(filename).unwrap());
    // let _tmps = template_parser::from_reader(&mut bufr);
    // let flows = pcap_analysis::dump_netflow("./rsc/netflows.pcapng", 2055);
    // println!("Flowsets num: {}", flows.len());
}
