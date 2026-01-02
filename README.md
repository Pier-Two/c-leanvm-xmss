# c-leanvm-xmss

C bindings for leanVM/leanMultisig XMSS signatures and aggregation.

## Scope

- XMSS key generation, signing, verification
- SSZ serialization/deserialization for keys and signatures
- LeanVM aggregation setup, aggregation, and verification

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

## Aggregated Signature Encoding

`pq_aggregate_signatures` returns a serialized proof with this layout:

```
byte 0   : version (0x01)
bytes 1-4: proof_len (u32 LE)
bytes 5-8: randomness_count (u32 LE)
bytes 9..: proof_bytes (length = proof_len)
then     : randomness_count * RAND_LEN_FE field elements
           each field element is a u32 LE
```

`RAND_LEN_FE` is the leanVM XMSS randomness length (currently 7).

`pq_verify_aggregated_signatures` expects this encoding.

## Notes

- Message length must be exactly 32 bytes (SSZ hash tree root).
- Use `pq_xmss_aggregation_setup_prover` / `pq_xmss_aggregation_setup_verifier`
  once at startup to avoid first-call latency.
