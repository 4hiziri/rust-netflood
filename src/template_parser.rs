use netflow::flowset::{
    DataTemplate, DataTemplateItem, FlowSet, OptionTemplate, OptionTemplateItem,
};
use netflow::netflow::NetFlow9;
use pcap_analysis;
use serde_json;
use std::io::Read;

#[allow(dead_code)]
fn from_str(template_str: &str) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_str::<serde_json::Value>(template_str) {
        Ok(_val) => Ok(DataTemplate::new(Vec::new())),
        Err(e) => Err(e),
    }
}

#[allow(dead_code)]
fn from_reader(template_reader: &mut Read) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_reader::<&mut Read, serde_json::Value>(template_reader) {
        Ok(_val) => Ok(DataTemplate::new(Vec::new())),
        Err(e) => Err(e),
    }
}

fn is_contained_template(vec: &[DataTemplateItem], item: &DataTemplateItem) -> bool {
    vec.into_iter().any(|i| i.template_id == item.template_id)
}

fn is_contained_option(vec: &[OptionTemplateItem], item: &OptionTemplate) -> bool {
    vec.into_iter()
        .any(|i| i.template_id == item.templates.template_id)
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
    templates.fold(Vec::new(), |mut acc, item| {
        if is_contained_template(&acc, &item) {
            acc
        } else {
            acc.push(item);
            acc
        }
    })
}

pub fn extract_option(filename: &str) -> Vec<OptionTemplateItem> {
    let option = pcap_analysis::dump_netflow(filename, 2055)
        .into_iter()
        .map(|packets| NetFlow9::from_bytes(&packets).unwrap())
        .flat_map(|netflow| {
            netflow.flow_sets.into_iter().filter_map(|set| match set {
                FlowSet::OptionTemplate(opt) => Some(opt),
                _ => None,
            })
        });

    // remove duplicates
    option.fold(Vec::new(), |mut acc, item| {
        if is_contained_option(&acc, &item) {
            acc
        } else {
            acc.push(item.templates);
            acc
        }
    })
}
