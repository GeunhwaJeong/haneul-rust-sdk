# haneul-graphql

[![haneul-graphql on crates.io](https://img.shields.io/crates/v/haneul-graphql)](https://crates.io/crates/haneul-graphql)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/haneul-graphql)
[![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://haneullabs.github.io/haneul-rust-sdk/haneul_graphql/)

A Rust client for interacting with the Haneul blockchain via its GraphQL API.
Provides typed methods for querying chain state, objects, transactions,
checkpoints, epochs, executing transactions, and more. For custom queries,
the companion [`haneul-graphql-macros`](https://crates.io/crates/haneul-graphql-macros)
crate offers `#[derive(Response)]` for ergonomic, compile-time validated
response deserialization.
