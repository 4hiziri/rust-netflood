use netflow::flowset::DataTemplate;
use serde_json;

pub fn from_str(template_str: &str) -> DataTemplate {
    let val: serde_json::Value = serde_json::from_str(template_str).unwrap();
    DataTemplate::new()
}
