#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define PUBLIC_KEY_SIZE 52

#define SIGNATURE_SIZE 424

#define SIGNATURE_SIZE 2536

typedef enum PQSigningError {
  Success = 0,
  EncodingAttemptsExceeded = 1,
  InvalidPointer = 2,
  InvalidMessageLength = 3,
  InvalidEpoch = 4,
  UnknownError = 99,
} PQSigningError;

typedef struct PQSignatureSchemeSecretKey {
  uint8_t _private[0];
} PQSignatureSchemeSecretKey;

typedef struct PQSignatureSchemePublicKey {
  uint8_t _private[0];
} PQSignatureSchemePublicKey;

typedef struct PQSignature {
  uint8_t _private[0];
} PQSignature;

typedef struct PQRange {
  uint64_t start;
  uint64_t end;
} PQRange;

typedef struct PQAggregatedSignatureChild {
  const struct PQSignatureSchemePublicKey *const *pubkeys;
  uintptr_t pubkey_count;
  const uint8_t *agg_bytes;
  uintptr_t agg_len;
} PQAggregatedSignatureChild;

typedef struct PQRawXmssSignature {
  const struct PQSignatureSchemePublicKey *pubkey;
  const struct PQSignature *signature;
} PQRawXmssSignature;

void pq_secret_key_free(struct PQSignatureSchemeSecretKey *key);

void pq_public_key_free(struct PQSignatureSchemePublicKey *key);

void pq_signature_free(struct PQSignature *signature);

void pq_string_free(char *s);

struct PQRange pq_get_activation_interval(const struct PQSignatureSchemeSecretKey *key);

struct PQRange pq_get_prepared_interval(const struct PQSignatureSchemeSecretKey *key);

void pq_advance_preparation(struct PQSignatureSchemeSecretKey *key);

uint64_t pq_get_lifetime(void);

uintptr_t pq_get_signature_size(void);

uintptr_t pq_get_public_key_size(void);

enum PQSigningError pq_key_gen(uintptr_t activation_epoch,
                               uintptr_t num_active_epochs,
                               struct PQSignatureSchemePublicKey **pk_out,
                               struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_sign(const struct PQSignatureSchemeSecretKey *sk,
                            uint64_t epoch,
                            const uint8_t *message,
                            uintptr_t message_len,
                            struct PQSignature **signature_out);

int pq_verify(const struct PQSignatureSchemePublicKey *pk,
              uint64_t epoch,
              const uint8_t *message,
              uintptr_t message_len,
              const struct PQSignature *signature);

int pq_verify_ssz(const uint8_t *pubkey_bytes,
                  uintptr_t pubkey_len,
                  uint64_t epoch,
                  const uint8_t *message,
                  uintptr_t message_len,
                  const uint8_t *signature_bytes,
                  uintptr_t signature_len);

char *pq_error_description(enum PQSigningError error);

enum PQSigningError pq_secret_key_serialize(const struct PQSignatureSchemeSecretKey *sk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_secret_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_secret_key_from_json(const uint8_t *json,
                                            uintptr_t json_len,
                                            struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_public_key_serialize(const struct PQSignatureSchemePublicKey *pk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_public_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemePublicKey **pk_out);

enum PQSigningError pq_public_key_from_json(const uint8_t *json,
                                            uintptr_t json_len,
                                            struct PQSignatureSchemePublicKey **pk_out);

enum PQSigningError pq_signature_serialize(const struct PQSignature *signature,
                                           uint8_t *buffer,
                                           uintptr_t buffer_len,
                                           uintptr_t *written_len);

enum PQSigningError pq_signature_deserialize(const uint8_t *buffer,
                                             uintptr_t buffer_len,
                                             struct PQSignature **signature_out);

enum PQSigningError pq_signature_from_json(const uint8_t *json,
                                           uintptr_t json_len,
                                           struct PQSignature **signature_out);

void pq_xmss_aggregation_setup_prover(void);

void pq_xmss_aggregation_setup_verifier(void);

enum PQSigningError pq_aggregate_signatures(const struct PQSignatureSchemePublicKey *const *pubkeys,
                                            const struct PQSignature *const *signatures,
                                            uintptr_t count,
                                            const uint8_t *message,
                                            uintptr_t message_len,
                                            uint64_t epoch,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_aggregate_signatures_recursive(const struct PQAggregatedSignatureChild *children,
                                                      uintptr_t child_count,
                                                      const struct PQRawXmssSignature *raw_xmss,
                                                      uintptr_t raw_xmss_count,
                                                      const uint8_t *message,
                                                      uintptr_t message_len,
                                                      uint64_t epoch,
                                                      uintptr_t log_inv_rate,
                                                      uint8_t *buffer,
                                                      uintptr_t buffer_len,
                                                      uintptr_t *written_len);

int pq_verify_aggregated_signatures(const struct PQSignatureSchemePublicKey *const *pubkeys,
                                    uintptr_t count,
                                    const uint8_t *message,
                                    uintptr_t message_len,
                                    const uint8_t *agg_bytes,
                                    uintptr_t agg_len,
                                    uint64_t epoch);
