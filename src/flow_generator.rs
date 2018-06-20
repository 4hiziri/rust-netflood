use generate_rand::rand_field;
use netflow::flowset::DataFlow;
use netflow::flowset::DataTemplateItem;

pub fn from_template(template: DataTemplateItem, count: usize) -> Vec<DataFlow> {
    let mut random_data = Vec::with_capacity(count);

    for _ in 0..count {
        random_data.push(rand_field(template.fields));
    }

    // TODO: wait for impl length method
    DataFlow::new(template.template_id, 0, random_data)
}
