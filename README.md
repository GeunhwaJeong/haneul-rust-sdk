# Haneul Rust Sdk

A rust sdk for integrating with the [Haneul blockchain](https://docs.haneul.io/).

## Overview

This repository contains a collection of libraries for integrating with the Haneul blockchain.

A few of the project's high-level goals are as follows:

* **Be modular** - user's should only need to pay the cost (in terms of dependencies/compilation time) for the features that they use.
* **Be light** - strive to have a minimal dependency footprint.
* **Support developers** - provide all needed types, abstractions and APIs to enable developers to build robust applications on Haneul.
* **Support wasm** - where possible, libraries should be usable in wasm environments.

## Crates

In an effort to be modular, functionality is split between a number of crates.

* [`haneul-sdk-types`](crates/haneul-sdk-types)
    [![haneul-sdk-types on crates.io](https://img.shields.io/crates/v/haneul-sdk-types)](https://crates.io/crates/haneul-sdk-types)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/haneul-sdk-types)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://haneullabs.github.io/haneul-rust-sdk/haneul_sdk_types/)
* [`haneul-crypto`](crates/haneul-crypto)
    [![haneul-crypto on crates.io](https://img.shields.io/crates/v/haneul-crypto)](https://crates.io/crates/haneul-crypto)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/haneul-crypto)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://haneullabs.github.io/haneul-rust-sdk/haneul_crypto/)
* [`haneul-rpc`](crates/haneul-rpc)
    [![haneul-rpc on crates.io](https://img.shields.io/crates/v/haneul-rpc)](https://crates.io/crates/haneul-rpc)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/haneul-rpc)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://haneullabs.github.io/haneul-rust-sdk/haneul_rpc/)
* [`haneul-transaction-builder`](crates/haneul-transaction-builder)
    [![haneul-transaction-builder on crates.io](https://img.shields.io/crates/v/haneul-transaction-builder)](https://crates.io/crates/haneul-transaction-builder)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/haneul-transaction-builder)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://haneullabs.github.io/haneul-rust-sdk/haneul_transaction_builder/)

## License

This project is available under the terms of the [Apache 2.0 license](LICENSE).
