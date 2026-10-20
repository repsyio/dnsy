//! Prints the `OpenAPI` document to stdout (`just openapi` redirects it to `openapi/dnsy.json`).

fn main() {
    let json = dnsy_api::openapi()
        .to_pretty_json()
        .expect("OpenAPI document serialises");
    println!("{json}");
}
