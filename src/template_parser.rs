use netflow::flowset::{DataTemplate, DataTemplateItem, FlowSet, OptionTemplateItem};
use netflow::netflow::NetFlow9;
use pcap_analysis;
use serde_json;
use std::io::Read;

fn from_str(template_str: &str) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_str::<serde_json::Value>(template_str) {
        Ok(_val) => Ok(DataTemplate::new(0, Vec::new())),
        Err(e) => Err(e),
    }
}

fn from_reader(template_reader: &mut Read) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_reader::<&mut Read, serde_json::Value>(template_reader) {
        Ok(_val) => Ok(DataTemplate::new(0, Vec::new())),
        Err(e) => Err(e),
    }
}

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
pub fn extract_template(filename: &str) -> Vec<DataTemplateItem> {
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

pub fn extract_option(filename: &str) -> Vec<OptionTemplateItem> {
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
