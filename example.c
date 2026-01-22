#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/leanvm-xmss.h"

int main(void) {
    struct PQSignatureSchemePublicKey *pubkey = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;

    printf("xmss example: starting\n");
    enum PQSigningError err = pq_key_gen(0, 1024, &pubkey, &secret);
    if (err != Success) {
        char *desc = pq_error_description(err);
        fprintf(stderr, "pq_key_gen failed: %s\n", desc ? desc : "unknown");
        pq_string_free(desc);
        return 1;
    }
    printf("xmss example: keygen ok\n");

    uint8_t message[32] = {0};
    struct PQSignature *signature = NULL;

    err = pq_sign(secret, 10, message, sizeof(message), &signature);
    if (err != Success) {
        char *desc = pq_error_description(err);
        fprintf(stderr, "pq_sign failed: %s\n", desc ? desc : "unknown");
        pq_string_free(desc);
        pq_public_key_free(pubkey);
        pq_secret_key_free(secret);
        return 1;
    }
    printf("xmss example: sign ok\n");

    int verify_result = pq_verify(pubkey, 10, message, sizeof(message), signature);
    if (verify_result != 1) {
        fprintf(stderr, "pq_verify failed: %d\n", verify_result);
    } else {
        printf("xmss example: verify ok\n");
    }

    const struct PQSignatureSchemePublicKey *pubkeys[1] = {pubkey};
    const struct PQSignature *signatures[1] = {signature};
    size_t agg_buf_len = 1024 * 1024;
    uint8_t *agg_buf = malloc(agg_buf_len);
    size_t agg_written = 0;

    if (!agg_buf) {
        fprintf(stderr, "failed to allocate aggregation buffer\n");
        pq_signature_free(signature);
        pq_public_key_free(pubkey);
        pq_secret_key_free(secret);
        return 1;
    }

    err = pq_aggregate_signatures(
        pubkeys,
        signatures,
        1,
        message,
        sizeof(message),
        10,
        agg_buf,
        agg_buf_len,
        &agg_written);
    if (err != Success && agg_written > agg_buf_len) {
        uint8_t *new_buf = realloc(agg_buf, agg_written);
        if (!new_buf) {
            fprintf(stderr, "failed to grow aggregation buffer to %zu bytes\n", agg_written);
            free(agg_buf);
            pq_signature_free(signature);
            pq_public_key_free(pubkey);
            pq_secret_key_free(secret);
            return 1;
        }
        agg_buf = new_buf;
        agg_buf_len = agg_written;
        err = pq_aggregate_signatures(
            pubkeys,
            signatures,
            1,
            message,
            sizeof(message),
            10,
            agg_buf,
            agg_buf_len,
            &agg_written);
    }
    if (err != Success) {
        char *desc = pq_error_description(err);
        fprintf(stderr, "pq_aggregate_signatures failed: %s\n", desc ? desc : "unknown");
        pq_string_free(desc);
    } else {
        printf("xmss example: aggregation ok, bytes=%zu\n", agg_written);
    }

    int agg_verify = pq_verify_aggregated_signatures(
        pubkeys,
        1,
        message,
        sizeof(message),
        agg_buf,
        agg_written,
        10);
    if (agg_verify != 1) {
        fprintf(stderr, "pq_verify_aggregated_signatures failed: %d\n", agg_verify);
    } else {
        printf("xmss example: aggregate verify ok\n");
    }

    free(agg_buf);
    pq_signature_free(signature);
    pq_public_key_free(pubkey);
    pq_secret_key_free(secret);

    printf("xmss example: done\n");
    return (verify_result == 1 && agg_verify == 1) ? 0 : 1;
}
