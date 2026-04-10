#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/leanvm-xmss.h"

static int check_error(enum PQSigningError err, const char *label) {
    if (err == Success) {
        return 1;
    }

    char *desc = pq_error_description(err);
    fprintf(stderr, "%s failed: %s\n", label, desc ? desc : "unknown");
    pq_string_free(desc);
    return 0;
}

static enum PQSigningError aggregate_single_signature(
    const struct PQSignatureSchemePublicKey *pubkey,
    const struct PQSignature *signature,
    const uint8_t *message,
    uint64_t epoch,
    uint8_t *buffer,
    size_t buffer_len,
    size_t *written_len) {
    const struct PQSignatureSchemePublicKey *pubkeys[1] = {pubkey};
    const struct PQSignature *signatures[1] = {signature};

    return pq_aggregate_signatures(
        pubkeys,
        signatures,
        1,
        message,
        32,
        epoch,
        buffer,
        buffer_len,
        written_len);
}

int main(void) {
    struct PQSignatureSchemePublicKey *pubkeys[3] = {NULL, NULL, NULL};
    struct PQSignatureSchemeSecretKey *secrets[3] = {NULL, NULL, NULL};
    struct PQSignature *signatures[3] = {NULL, NULL, NULL};
    uint8_t message[32] = {0};
    uint8_t *child_one_bytes = NULL;
    uint8_t *child_two_bytes = NULL;
    uint8_t *final_bytes = NULL;
    size_t child_one_written = 0;
    size_t child_two_written = 0;
    size_t final_written = 0;
    int exit_code = 1;

    printf(
        "xmss example: public_key_size=%zu signature_size=%zu lifetime=%llu\n",
        (size_t)pq_get_public_key_size(),
        (size_t)pq_get_signature_size(),
        (unsigned long long)pq_get_lifetime());

    pq_xmss_aggregation_setup_prover();

    for (size_t i = 0; i < 3; ++i) {
        if (!check_error(pq_key_gen(0, 1024, &pubkeys[i], &secrets[i]), "pq_key_gen")) {
            goto cleanup;
        }
        if (!check_error(
                pq_sign(secrets[i], 10, message, sizeof(message), &signatures[i]),
                "pq_sign")) {
            goto cleanup;
        }
    }
    printf("xmss example: generated 3 signatures\n");

    if (pq_verify(pubkeys[0], 10, message, sizeof(message), signatures[0]) != 1) {
        fprintf(stderr, "pq_verify failed for signer 0\n");
        goto cleanup;
    }
    printf("xmss example: raw verify ok\n");

    child_one_bytes = malloc(512u * 1024u);
    child_two_bytes = malloc(512u * 1024u);
    final_bytes = malloc(1024u * 1024u);
    if (!child_one_bytes || !child_two_bytes || !final_bytes) {
        fprintf(stderr, "failed to allocate aggregation buffers\n");
        goto cleanup;
    }

    if (!check_error(
            aggregate_single_signature(
                pubkeys[0],
                signatures[0],
                message,
                10,
                child_one_bytes,
                512u * 1024u,
                &child_one_written),
            "pq_aggregate_signatures(child 1)")) {
        goto cleanup;
    }
    if (!check_error(
            aggregate_single_signature(
                pubkeys[1],
                signatures[1],
                message,
                10,
                child_two_bytes,
                512u * 1024u,
                &child_two_written),
            "pq_aggregate_signatures(child 2)")) {
        goto cleanup;
    }
    printf(
        "xmss example: child proofs ok, bytes=[%zu, %zu]\n",
        child_one_written,
        child_two_written);

    const struct PQSignatureSchemePublicKey *child_one_pubkeys[1] = {pubkeys[0]};
    const struct PQSignatureSchemePublicKey *child_two_pubkeys[1] = {pubkeys[1]};
    const struct PQSignatureSchemePublicKey *final_pubkeys[3] = {pubkeys[0], pubkeys[1], pubkeys[2]};
    const struct PQRawXmssSignature raw_xmss[1] = {{
        .pubkey = pubkeys[2],
        .signature = signatures[2],
    }};
    const struct PQAggregatedSignatureChild children[2] = {{
        .pubkeys = child_one_pubkeys,
        .pubkey_count = 1,
        .agg_bytes = child_one_bytes,
        .agg_len = child_one_written,
    },
    {
        .pubkeys = child_two_pubkeys,
        .pubkey_count = 1,
        .agg_bytes = child_two_bytes,
        .agg_len = child_two_written,
    }};

    if (!check_error(
            pq_aggregate_signatures_recursive(
                children,
                2,
                raw_xmss,
                1,
                message,
                sizeof(message),
                10,
                2,
                final_bytes,
                1024u * 1024u,
                &final_written),
            "pq_aggregate_signatures_recursive")) {
        goto cleanup;
    }
    printf("xmss example: recursive aggregation ok, bytes=%zu\n", final_written);

    pq_xmss_aggregation_setup_verifier();
    if (pq_verify_aggregated_signatures(
            final_pubkeys,
            3,
            message,
            sizeof(message),
            final_bytes,
            final_written,
            10)
        != 1) {
        fprintf(stderr, "pq_verify_aggregated_signatures failed for recursive proof\n");
        goto cleanup;
    }
    printf("xmss example: recursive aggregate verify ok\n");

    exit_code = 0;

cleanup:
    free(final_bytes);
    free(child_two_bytes);
    free(child_one_bytes);

    for (size_t i = 0; i < 3; ++i) {
        pq_signature_free(signatures[i]);
        pq_public_key_free(pubkeys[i]);
        pq_secret_key_free(secrets[i]);
    }

    return exit_code;
}
