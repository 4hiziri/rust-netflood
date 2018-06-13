use netflow::flowset::{DataTemplateItem, OptionTemplateItem};
use serde_json;

pub fn dump_template(template: &DataTemplateItem) -> Result<(), serde_json::Error> {
    let val = json!(template);
    println!("json: {}", val);

    // let val2 = serde_json::to_vec(&template.fields);
    // println!("json: {:?}", val2);

    Ok(())
}

// pub fn dump_option(template: DataTemplateItem) -> Result<(), serde_json::Error> {

// }
