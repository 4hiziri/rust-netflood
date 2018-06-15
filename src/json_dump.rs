use netflow::flowset::{DataTemplateItem, OptionTemplateItem};
use serde_json::Error;

pub fn dump_template(template: &Vec<DataTemplateItem>) -> Result<String, Error> {
    let val = json!(template);

    Ok(val.to_string())
}

pub fn dump_option(option: &Vec<OptionTemplateItem>) -> Result<String, Error> {
    let val = json!(option);

    Ok(val.to_string())
}
