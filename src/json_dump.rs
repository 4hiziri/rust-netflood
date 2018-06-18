use netflow::flowset::{DataTemplateItem, OptionTemplateItem};
use serde_json;
use serde_json::Error;
use std::fs::File;
use std::io::{BufReader, Read};

pub fn dump_template(template: &Vec<DataTemplateItem>) -> Result<String, Error> {
    let val = json!(template);

    Ok(val.to_string())
}

pub fn dump_option(option: &Vec<OptionTemplateItem>) -> Result<String, Error> {
    let val = json!(option);

    Ok(val.to_string())
}

// TODO: impl generator from range object
pub fn json_template(filename: &str) -> Vec<DataTemplateItem> {
    let mut fd = File::open(filename).unwrap();
    let mut reader = BufReader::new(fd);

    let template: Vec<DataTemplateItem> = serde_json::from_reader(reader).unwrap();

    template
}

pub fn json_option(filename: &str) -> Vec<OptionTemplateItem> {
    let mut fd = File::open(filename).unwrap();
    let mut reader = BufReader::new(fd);

    let template: Vec<OptionTemplateItem> = serde_json::from_reader(reader).unwrap();

    template
}
