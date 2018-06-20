use netflow::field::{FieldValue, FlowField, TypeLengthField};
use netflow::flowset::Record;
use rand::prelude::*;

pub fn rand_field(templates: Vec<TypeLengthField>) -> Record {
    let mut records: Vec<FlowField> = Vec::with_capacity(templates.len());

    for template in templates {
        let mut field_val: Vec<u8> = Vec::with_capacity(template.length as usize);

        // TODO: extract Vec of random value method
        // TODO: some value may not work
        for _ in 0..template.length {
            field_val.push(random());
        }

        records.push(FlowField::new(
            template.type_id,
            template.length,
            FieldValue::new(template.type_id, &field_val),
        ));
    }

    Record::make_data(records)
}
