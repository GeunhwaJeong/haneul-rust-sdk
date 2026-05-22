//! GraphQL client for the [Haneul] blockchain.
//!
//! [Haneul]: https://haneul.io
//!
//! This crate provides a typed GraphQL client for Haneul's GraphQL API with
//! automatic BCS deserialization and pagination support.
//!
//! # Quick Start
//!
//! ```no_run
//! use haneul_graphql::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::new(Client::MAINNET)?;
//!
//!     // Chain info
//!     let chain_id = client.chain_identifier().await?;
//!     println!("Chain: {chain_id}");
//!
//!     // Fetch objects, transactions, checkpoints
//!     let obj = client.get_object("0x5".parse()?).await?;
//!     let tx = client.get_transaction("digest...").await?;
//!     let cp = client.get_checkpoint(None).await?; // latest
//!
//!     Ok(())
//! }
//! ```
//!
//! # Streaming
//!
//! List methods return async streams with automatic pagination:
//!
//! ```no_run
//! use futures::StreamExt;
//! use std::pin::pin;
//! use haneul_graphql::Client;
//! use haneul_sdk_types::Address;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::new(Client::MAINNET)?;
//!     let owner: Address = "0x123...".parse()?;
//!
//!     let mut stream = pin!(client.list_objects(owner));
//!     while let Some(obj) = stream.next().await {
//!         let obj = obj?;
//!         println!("Object version: {}", obj.version());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Custom Queries
//!
//! For queries beyond the built-in methods, use [`Client::query`] with a
//! response type that implements [`serde::de::DeserializeOwned`]. The
//! [`haneul-graphql-macros`] crate provides `graphql_query!` to validate the
//! query string and `#[derive(Response)]` to generate the response
//! deserialization code, both checked against the Haneul GraphQL schema at
//! compile time.
//!
//! [`haneul-graphql-macros`]: https://docs.rs/haneul-graphql-macros
//!
//! ```no_run
//! use haneul_graphql::Client;
//! use haneul_graphql_macros::Response;
//! use haneul_graphql_macros::graphql_query;
//!
//! // Define a response type with field paths into the GraphQL response JSON.
//! // Paths are validated against the schema at compile time — typos like
//! // "epoch.epochIdd" will produce a compile error with a "Did you mean?" suggestion.
//! #[derive(Response)]
//! struct MyResponse {
//!     #[field(path = "epoch.epochId")]
//!     epoch_id: u64,
//!     // Use `[]` to extract items from a list field
//!     #[field(path = "epoch.checkpoints.nodes[].digest")]
//!     checkpoint_digests: Vec<String>,
//!     // Use `?` to mark nullable fields — null returns Ok(None) instead of an error.
//!     // Without `?`, a null value at that segment is a runtime error.
//!     #[field(path = "epoch.referenceGasPrice?")]
//!     gas_price: Option<u64>,
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), haneul_graphql::Error> {
//!     let client = Client::new(Client::MAINNET)?;
//!
//!     // `graphql_query!` validates the query against the schema at compile time.
//!     const QUERY: &str = graphql_query!(
//!         "query($epochId: UInt53) {
//!             epoch(epochId: $epochId) {
//!                 epochId
//!                 checkpoints { nodes { digest } }
//!                 referenceGasPrice
//!             }
//!         }"
//!     );
//!     let variables = serde_json::json!({ "epochId": 100 });
//!
//!     let response = client.query::<MyResponse>(QUERY, variables).await?;
//!
//!     // GraphQL supports partial success — data and errors can coexist
//!     for err in response.errors() {
//!         eprintln!("GraphQL error: {}", err.message());
//!     }
//!     if let Some(data) = response.data() {
//!         println!("Epoch: {}", data.epoch_id);
//!         println!("Checkpoints: {:?}", data.checkpoint_digests);
//!         println!("Gas price: {:?}", data.gas_price);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! For the full path syntax reference (`?`, `[]`, aliases, enums), see the
//! [`haneul-graphql-macros` documentation](https://docs.rs/haneul-graphql-macros).
//!
//! See [`Client`] for the full list of available methods.

mod bcs;
mod client;
mod error;
mod move_value;
mod pagination;
mod response;
pub mod scalars;

/// Re-export of [`reqwest::header`] so callers using
/// [`Client::with_headers`](crate::Client::with_headers) /
/// [`Client::extend_headers`](crate::Client::extend_headers) don't need to add
/// `reqwest` as a direct dependency.
pub use reqwest::header;

pub use bcs::Bcs;
pub use bcs::BcsBytes;
pub use client::Client;
pub use client::chain::Epoch;
pub use client::checkpoints::CheckpointResponse;
pub use client::coins::Balance;
pub use client::dynamic_fields::DynamicField;
pub use client::dynamic_fields::DynamicFieldRequest;
pub use client::dynamic_fields::DynamicFieldValue;
pub use client::dynamic_fields::DynamicFieldsRequest;
pub use client::dynamic_fields::Format;
pub use client::execution::ExecutionResult;
pub use client::transactions::TransactionResponse;
pub use error::Error;
pub use error::GraphQLError;
pub use error::Location;
pub use error::PathFragment;
pub use haneul_graphql_macros::graphql_query;
pub use move_value::MoveObject;
pub use move_value::MoveValue;
pub use pagination::Page;
pub use pagination::PageInfo;
pub use pagination::paginate;
pub use pagination::paginate_backward;
pub use response::Response;
