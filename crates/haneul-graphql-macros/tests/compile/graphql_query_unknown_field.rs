//! trybuild compile-fail: a typo in a field name is rejected against the schema.

use haneul_graphql_macros::graphql_query;

const Q: &str = graphql_query!("query { chainIdentifierr }");

fn main() {
    let _ = Q;
}
