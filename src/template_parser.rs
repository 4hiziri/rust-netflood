use netflow::flowset::DataTemplate;
use serde_json;
use std::io::Read;

pub fn from_str(template_str: &str) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_str::<serde_json::Value>(template_str) {
        Ok(_val) => Ok(DataTemplate::new(0, 0, 0, Vec::new())),
        Err(e) => Err(e),
    }
}

pub fn from_reader(template_reader: &mut Read) -> Result<DataTemplate, serde_json::Error> {
    match serde_json::from_reader::<&mut Read, serde_json::Value>(template_reader) {
        Ok(_val) => Ok(DataTemplate::new(0, 0, 0, Vec::new())),
        Err(e) => Err(e),
    }
}
