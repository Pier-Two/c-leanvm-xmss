# c-leanvm-xmss

C bindings for leanVM/leanMultisig XMSS signatures and aggregation.

## Scope

- XMSS key generation, signing, verification
- SSZ serialization/deserialization for keys and signatures
- LeanVM aggregation setup, raw aggregation, recursive aggregation, and verification

The API mirrors `c-hash-sig` where possible to keep integration minimal.

## Build

```bash
cargo build --release
```

Outputs:
- Static library: `target/release/libleanvm_xmss_c.a`
- Dynamic library: `target/release/libleanvm_xmss_c.{so,dylib,dll}`
- Header: `include/leanvm-xmss.h`

A compatibility header is provided at `include/pq-bindings-c-rust.h`.

## Devnet4 Notes

- XMSS public keys remain 52 bytes.
- Devnet4 XMSS signatures are 2536 bytes in canonical SSZ form.
- `pq_signature_deserialize` and `pq_verify_ssz` also accept legacy 3112-byte buffers
  when the trailing bytes are zero, which helps with staged downstream migrations.

## Aggregated Proof Encoding

`pq_aggregate_signatures` and `pq_aggregate_signatures_recursive` return the upstream
devnet4 `AggregatedXMSS` byte format from `leanMultisig`.

That format is:
- postcard serialization of the `AggregatedXMSS` Rust struct
- wrapped in `lz4_flex::compress_prepend_size`

`pq_verify_aggregated_signatures` expects this exact encoding.

## Notes

- Message length must be exactly 32 bytes (SSZ hash tree root).
- Use `pq_xmss_aggregation_setup_prover` / `pq_xmss_aggregation_setup_verifier`
  once at startup to avoid first-call latency.
- `pq_aggregate_signatures_recursive` accepts child proofs plus raw XMSS signatures so
  callers can build recursive proofs without flattening them first.
