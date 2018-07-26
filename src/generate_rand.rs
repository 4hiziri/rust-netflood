use netflow::field::{FieldValue, FlowField, TypeLengthField};
use netflow::flowset::Record;
use rand::prelude::*;

pub fn rand_field(templates: &Vec<TypeLengthField>) -> Record {
    let mut records: Vec<FlowField> = Vec::with_capacity(templates.len());

    for template in templates {
        let mut field_val: Vec<u8> = Vec::with_capacity(template.length as usize);

        // TODO: extract Vec of random value method
        // TODO: some value may not work
        for _ in 0..template.length {
            field_val.push(random());
        }

        let field_val = FieldValue::new(template.type_id, &field_val);

        records.push(FlowField::new(template.type_id, template.length, field_val));
    }

    Record::make_data(records)
}

#[test]
fn test_rand_field() {
    use generate_rand::rand_field;
    use netflow::field::TypeLengthField;

    let mut temps = Vec::new();
    temps.push(TypeLengthField::new(100, 2));
    temps.push(TypeLengthField::new(101, 4));
    temps.push(TypeLengthField::new(102, 8));
    temps.push(TypeLengthField::new(103, 5));

    let record = rand_field(&temps);

    assert_eq!(record.to_bytes().len(), 19);
}
