/// Chain ID of the current chain
pub const X_HANEUL_CHAIN_ID: &str = "x-haneul-chain-id";

/// Chain name of the current chain
pub const X_HANEUL_CHAIN: &str = "x-haneul-chain";

/// Current checkpoint height
pub const X_HANEUL_CHECKPOINT_HEIGHT: &str = "x-haneul-checkpoint-height";

/// Lowest available checkpoint for which transaction and checkpoint data can be requested.
///
/// Specifically this is the lowest checkpoint for which the following data can be requested:
///  - checkpoints
///  - transactions
///  - effects
///  - events
pub const X_HANEUL_LOWEST_AVAILABLE_CHECKPOINT: &str = "x-haneul-lowest-available-checkpoint";

/// Lowest available checkpoint for which object data can be requested.
///
/// Specifically this is the lowest checkpoint for which input/output object data will be
/// available.
pub const X_HANEUL_LOWEST_AVAILABLE_CHECKPOINT_OBJECTS: &str =
    "x-haneul-lowest-available-checkpoint-objects";

/// Current epoch of the chain
pub const X_HANEUL_EPOCH: &str = "x-haneul-epoch";

/// Current timestamp of the chain - represented as number of milliseconds from the Unix epoch
pub const X_HANEUL_TIMESTAMP_MS: &str = "x-haneul-timestamp-ms";

/// Current timestamp of the chain - encoded in the [RFC 3339] format.
///
/// [RFC 3339]: https://www.ietf.org/rfc/rfc3339.txt
pub const X_HANEUL_TIMESTAMP: &str = "x-haneul-timestamp";

/// Request header carrying the highest protocol version whose types the client can decode.
///
/// The server may use it to avoid sending data the client cannot decode.
pub const X_HANEUL_CLIENT_PROTOCOL_VERSION: &str = "x-haneul-client-protocol-version";

/// Highest Haneul protocol version whose on-chain types this SDK can decode, sent as
/// [`X_HANEUL_CLIENT_PROTOCOL_VERSION`].
///
/// Bump this when the SDK gains support for types introduced in a newer protocol version.
pub const MAX_PROTOCOL_VERSION: u64 = 128;
