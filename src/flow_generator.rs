use generate_rand::rand_field;
use netflow::field::TypeLengthField;
use netflow::flowset::{DataFlow, DataTemplateItem, OptionTemplateItem};

fn from_fields(id: u16, fields: &Vec<TypeLengthField>, count: usize) -> Vec<DataFlow> {
    let mut dataflow = Vec::with_capacity(count);

    for _ in 0..count {
        let mut random_data = Vec::with_capacity(count);

        for _ in 0..count {
            random_data.push(rand_field(fields));
        }

        let record_len = random_data
            .as_slice()
            .into_iter()
            .fold(0, |sum, rec| sum + rec.byte_length()) as u16;

        dataflow.push(DataFlow::new(id, record_len + 4 + 4, random_data));
    }

    dataflow
}

pub fn from_template(template: DataTemplateItem, count: usize) -> Vec<DataFlow> {
    self::from_fields(template.template_id, &template.fields, count)
}

pub fn from_option(option: OptionTemplateItem, count: usize) -> Vec<DataFlow> {
    let mut template = option.scopes.clone();
    template.append(&mut option.options.clone());

    self::from_fields(option.template_id, &template, count)
}
