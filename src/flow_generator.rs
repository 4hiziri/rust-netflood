use generate_rand::rand_field;
use netflow::flowset::DataFlow;
use netflow::flowset::DataTemplateItem;

pub fn from_template(template: DataTemplateItem, count: usize) -> Vec<DataFlow> {
    let mut dataflow = Vec::with_capacity(count);
    let template_id = template.template_id;
    let template = &template.fields;

    for _ in 0..count {
        let mut random_data = Vec::with_capacity(count);

        for _ in 0..count {
            random_data.push(rand_field(template));
        }

        // TODO: wait for impl length method
        dataflow.push(DataFlow::new(template_id, 0, random_data));
    }

    dataflow
}
