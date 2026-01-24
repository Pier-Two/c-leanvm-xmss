use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::slice;

use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use leansig::serialization::Serializable;
use leansig::MESSAGE_LENGTH;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use ssz::{Decode, Encode};

use rec_aggregation::xmss_aggregate::{
    xmss_aggregate_signatures, xmss_setup_aggregation_program, xmss_verify_aggregated_signatures,
    Devnet2XmssAggregateSignature, XmssAggregateError,
};
use rec_aggregation::xmss_aggregate::config::{LeanSigPubKey, LeanSigScheme, LeanSigSignature};

// Public key size is fixed at 52 bytes (8 + 5 KoalaBear field elements * 4 bytes each)
pub const PUBLIC_KEY_SIZE: usize = 52;
// Signature size for XMSS configuration.
pub const SIGNATURE_SIZE: usize = 3112;

const AGG_SIGNATURE_VERSION: u8 = 1u8;
const AGG_SIGNATURE_HEADER_LEN: usize = 1 + 4 + 4;
const AGG_SIGNATURE_FIELD_BYTES: usize = 4;
const AGG_RANDOMNESS_LEN: usize =
    leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::RAND_LEN_FE;

// Type aliases for convenience
type PublicKeyType = LeanSigPubKey;
type SecretKeyType = <LeanSigScheme as SignatureScheme>::SecretKey;
type SignatureType = LeanSigSignature;

type FieldElement = KoalaBear;

/// Wrapper for signature scheme secret key
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignatureSchemeSecretKey {
    _private: [u8; 0],
}

/// Wrapper for signature scheme public key
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignatureSchemePublicKey {
    _private: [u8; 0],
}

/// Wrapper for signature
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignature {
    _private: [u8; 0],
}

// Internal wrappers (not exported to C)
struct PQSignatureSchemeSecretKeyInner {
    inner: Box<SecretKeyType>,
}

struct PQSignatureSchemePublicKeyInner {
    inner: Box<PublicKeyType>,
}

struct PQSignatureInner {
    inner: Box<SignatureType>,
}

/// Range representation for C
#[repr(C)]
pub struct PQRange {
    pub start: u64,
    pub end: u64,
}

impl From<std::ops::Range<u64>> for PQRange {
    fn from(range: std::ops::Range<u64>) -> Self {
        PQRange {
            start: range.start,
            end: range.end,
        }
    }
}

/// Error codes for signature scheme
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PQSigningError {
    /// Success (not an error)
    Success = 0,
    /// Failed to encode message after maximum number of attempts
    EncodingAttemptsExceeded = 1,
    /// Invalid pointer (null pointer)
    InvalidPointer = 2,
    /// Invalid message length
    InvalidMessageLength = 3,
    /// Epoch outside supported range
    InvalidEpoch = 4,
    /// Unknown error
    UnknownError = 99,
}

// ============================================================================
// Memory management functions
// ============================================================================

/// Frees memory allocated for secret key
/// # Safety
/// Pointer must be valid and created via pq_key_gen
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_free(key: *mut PQSignatureSchemeSecretKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemeSecretKeyInner);
    }
}

/// Frees memory allocated for public key
/// # Safety
/// Pointer must be valid and created via pq_key_gen
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_free(key: *mut PQSignatureSchemePublicKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemePublicKeyInner);
    }
}

/// Frees memory allocated for signature
/// # Safety
/// Pointer must be valid and created via pq_sign
#[no_mangle]
pub unsafe extern "C" fn pq_signature_free(signature: *mut PQSignature) {
    if !signature.is_null() {
        let _ = Box::from_raw(signature as *mut PQSignatureInner);
    }
}

/// Frees memory allocated for error description string
/// # Safety
/// Pointer must be valid and created via pq_error_description
#[no_mangle]
pub unsafe extern "C" fn pq_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ============================================================================
// SignatureSchemeSecretKey functions
// ============================================================================

/// Get key activation interval
/// # Safety
/// Pointer must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_get_activation_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.get_activation_interval().into()
}

/// Get prepared interval of the key
/// # Safety
/// Pointer must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_get_prepared_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.get_prepared_interval().into()
}

/// Advance key preparation to next interval
/// # Safety
/// Pointer must be valid and mutable
#[no_mangle]
pub unsafe extern "C" fn pq_advance_preparation(key: *mut PQSignatureSchemeSecretKey) {
    if key.is_null() {
        return;
    }
    let key = &mut *(key as *mut PQSignatureSchemeSecretKeyInner);
    key.inner.advance_preparation();
}

// ============================================================================
// SignatureScheme functions
// ============================================================================

/// Get maximum lifetime of signature scheme
#[no_mangle]
pub extern "C" fn pq_get_lifetime() -> u64 {
    LeanSigScheme::LIFETIME
}

/// Get signature size in bytes
#[no_mangle]
pub extern "C" fn pq_get_signature_size() -> usize {
    SIGNATURE_SIZE
}

/// Get public key size in bytes
#[no_mangle]
pub extern "C" fn pq_get_public_key_size() -> usize {
    PUBLIC_KEY_SIZE
}

/// Generate key pair (public and secret)
///
/// # Parameters
/// - `activation_epoch`: starting epoch for key activation
/// - `num_active_epochs`: number of active epochs
/// - `pk_out`: pointer to write public key (output)
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// Pointers pk_out and sk_out must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_key_gen(
    activation_epoch: usize,
    num_active_epochs: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if pk_out.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let mut rng = rand::rng();
    let (pk, sk) = LeanSigScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);

    let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(pk),
    });
    let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(sk),
    });

    *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
    *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;

    PQSigningError::Success
}

/// Sign a message
///
/// # Parameters
/// - `sk`: secret key for signing
/// - `epoch`: epoch for which signature is created
/// - `message`: pointer to message
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_sign(
    sk: *const PQSignatureSchemeSecretKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if sk.is_null() || message.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if message_len != MESSAGE_LENGTH {
        return PQSigningError::InvalidMessageLength;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return PQSigningError::InvalidEpoch,
    };

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);
    let message_slice = slice::from_raw_parts(message, message_len);

    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    match LeanSigScheme::sign(&sk.inner, epoch32, &message_array) {
        Ok(signature) => {
            let sig_wrapper = Box::new(PQSignatureInner {
                inner: Box::new(signature),
            });
            *signature_out = Box::into_raw(sig_wrapper) as *mut PQSignature;
            PQSigningError::Success
        }
        Err(leansig::signature::SigningError::EncodingAttemptsExceeded { .. }) => {
            PQSigningError::EncodingAttemptsExceeded
        }
    }
}

/// Verify a signature
///
/// # Parameters
/// - `pk`: public key
/// - `epoch`: signature epoch
/// - `message`: pointer to message
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature`: signature to verify
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_verify(
    pk: *const PQSignatureSchemePublicKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature: *const PQSignature,
) -> c_int {
    if pk.is_null() || message.is_null() || signature.is_null() {
        return -1;
    }

    if message_len != MESSAGE_LENGTH {
        return -2;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return -3,
    };

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    let signature = &*(signature as *const PQSignatureInner);
    let message_slice = slice::from_raw_parts(message, message_len);

    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    let is_valid = LeanSigScheme::verify(&pk.inner, epoch32, &message_array, &signature.inner);

    if is_valid {
        1
    } else {
        0
    }
}

/// Verify a signature from SSZ-serialized bytes
///
/// This function deserializes the public key and signature from SSZ format
/// and verifies the signature.
///
/// # Parameters
/// - `pubkey_bytes`: pointer to SSZ-serialized public key bytes (52 bytes)
/// - `pubkey_len`: length of public key bytes
/// - `epoch`: signature epoch
/// - `message`: pointer to message (must be 32 bytes)
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature_bytes`: pointer to SSZ-serialized signature bytes
/// - `signature_len`: length of signature bytes
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
///
/// # Safety
/// All pointers must be valid and point to correctly sized data
#[no_mangle]
pub unsafe extern "C" fn pq_verify_ssz(
    pubkey_bytes: *const u8,
    pubkey_len: usize,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_bytes: *const u8,
    signature_len: usize,
) -> c_int {
    if pubkey_bytes.is_null() || message.is_null() || signature_bytes.is_null() {
        return -1;
    }

    if message_len != MESSAGE_LENGTH {
        return -2;
    }

    if pubkey_len != PUBLIC_KEY_SIZE {
        return -7;
    }

    if signature_len != SIGNATURE_SIZE {
        return -8;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return -3,
    };

    let pk_data = slice::from_raw_parts(pubkey_bytes, pubkey_len);
    let sig_data = slice::from_raw_parts(signature_bytes, signature_len);
    let msg_data = slice::from_raw_parts(message, message_len);

    let message_array: &[u8; MESSAGE_LENGTH] = match msg_data.try_into() {
        Ok(arr) => arr,
        Err(_) => return -4,
    };

    let pk = match PublicKeyType::from_bytes(pk_data) {
        Ok(value) => value,
        Err(_) => return -5,
    };

    let sig = match SignatureType::from_bytes(sig_data) {
        Ok(value) => value,
        Err(_) => return -6,
    };

    let is_valid = LeanSigScheme::verify(&pk, epoch32, message_array, &sig);

    if is_valid {
        1
    } else {
        0
    }
}

// ============================================================================
// Error handling
// ============================================================================

/// Get error description string
///
/// # Parameters
/// - `error`: error code
///
/// # Returns
/// Pointer to C-string with error description.
/// Memory must be freed using pq_string_free
///
/// # Safety
/// Returned pointer must be freed by caller
#[no_mangle]
pub extern "C" fn pq_error_description(error: PQSigningError) -> *mut c_char {
    let desc = match error {
        PQSigningError::Success => "Success",
        PQSigningError::EncodingAttemptsExceeded => "Encoding attempts exceeded",
        PQSigningError::InvalidPointer => "Invalid pointer",
        PQSigningError::InvalidMessageLength => "Invalid message length",
        PQSigningError::InvalidEpoch => "Invalid epoch",
        PQSigningError::UnknownError => "Unknown error",
    };

    CString::new(desc).unwrap().into_raw()
}

// ============================================================================
// Serialization functions
// ============================================================================

/// Serialize secret key to bytes using SSZ format
///
/// # Parameters
/// - `sk`: secret key
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_serialize(
    sk: *const PQSignatureSchemeSecretKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if sk.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);
    let bytes = sk.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError;
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize secret key from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if buffer.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match SecretKeyType::from_bytes(buffer_slice) {
        Ok(sk) => {
            let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
                inner: Box::new(sk),
            });
            *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

/// Deserialize secret key from JSON
///
/// # Parameters
/// - `json`: pointer to UTF-8 JSON buffer
/// - `json_len`: buffer size
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_from_json(
    json: *const u8,
    json_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if json.is_null() || sk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(s) => s,
        Err(_) => return PQSigningError::UnknownError,
    };

    match serde_json::from_str::<SecretKeyType>(json_str) {
        Ok(sk) => {
            let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
                inner: Box::new(sk),
            });
            *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

/// Serialize public key to bytes using SSZ format
///
/// # Parameters
/// - `pk`: public key
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_serialize(
    pk: *const PQSignatureSchemePublicKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if pk.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    let bytes = pk.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError;
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize public key from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `pk_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if buffer.is_null() || pk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match PublicKeyType::from_bytes(buffer_slice) {
        Ok(pk) => {
            let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
                inner: Box::new(pk),
            });
            *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

/// Deserialize public key from JSON
///
/// # Parameters
/// - `json`: pointer to UTF-8 JSON buffer
/// - `json_len`: buffer size
/// - `pk_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_from_json(
    json: *const u8,
    json_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if json.is_null() || pk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(s) => s,
        Err(_) => return PQSigningError::UnknownError,
    };

    match serde_json::from_str::<PublicKeyType>(json_str) {
        Ok(pk) => {
            let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
                inner: Box::new(pk),
            });
            *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

/// Serialize signature to bytes using SSZ format
///
/// # Parameters
/// - `signature`: signature
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_serialize(
    signature: *const PQSignature,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if signature.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let signature = &*(signature as *const PQSignatureInner);

    let bytes = signature.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError;
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize signature from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if buffer.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match SignatureType::from_bytes(buffer_slice) {
        Ok(signature) => {
            let sig_wrapper = Box::new(PQSignatureInner {
                inner: Box::new(signature),
            });
            *signature_out = Box::into_raw(sig_wrapper) as *mut PQSignature;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

// ============================================================================
// Aggregation functions
// ============================================================================

/// Setup the prover for XMSS aggregation.
#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_prover() {
    xmss_setup_aggregation_program();
}

/// Setup the verifier for XMSS aggregation.
#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_verifier() {
    xmss_setup_aggregation_program();
}

fn serialize_agg_signature(sig: &Devnet2XmssAggregateSignature) -> Vec<u8> {
    sig.as_ssz_bytes()
}

fn deserialize_agg_signature(data: &[u8]) -> Result<Devnet2XmssAggregateSignature, PQSigningError> {
    if let Ok(sig) = Devnet2XmssAggregateSignature::from_ssz_bytes(data) {
        return Ok(sig);
    }

    if data.len() < AGG_SIGNATURE_HEADER_LEN {
        return Err(PQSigningError::UnknownError);
    }

    let version = data[0];
    if version != AGG_SIGNATURE_VERSION {
        return Err(PQSigningError::UnknownError);
    }

    let proof_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let randomness_count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

    let mut offset = AGG_SIGNATURE_HEADER_LEN;
    if data.len() < offset + proof_len {
        return Err(PQSigningError::UnknownError);
    }

    let proof_bytes = data[offset..offset + proof_len].to_vec();
    offset += proof_len;

    if randomness_count == 0 {
        return Ok(Devnet2XmssAggregateSignature {
            proof_bytes,
            encoding_randomness: Vec::new(),
        });
    }

    let randomness_len = AGG_RANDOMNESS_LEN;
    let expected_randomness_bytes = randomness_count
        .checked_mul(randomness_len)
        .and_then(|len| len.checked_mul(AGG_SIGNATURE_FIELD_BYTES))
        .ok_or(PQSigningError::UnknownError)?;

    if data.len() != offset + expected_randomness_bytes {
        return Err(PQSigningError::UnknownError);
    }

    let mut encoding_randomness = Vec::with_capacity(randomness_count);
    for _ in 0..randomness_count {
        let mut entry = [FieldElement::from_u32(0); AGG_RANDOMNESS_LEN];
        for j in 0..randomness_len {
            let start = offset + (j * AGG_SIGNATURE_FIELD_BYTES);
            let value = u32::from_le_bytes([
                data[start],
                data[start + 1],
                data[start + 2],
                data[start + 3],
            ]);
            entry[j] = FieldElement::from_u32(value);
        }
        encoding_randomness.push(entry);
        offset += randomness_len * AGG_SIGNATURE_FIELD_BYTES;
    }

    Ok(Devnet2XmssAggregateSignature {
        proof_bytes,
        encoding_randomness,
    })
}

fn collect_public_keys(
    keys: *const *const PQSignatureSchemePublicKey,
    count: usize,
) -> Result<Vec<PublicKeyType>, PQSigningError> {
    if keys.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let key_ptrs = unsafe { slice::from_raw_parts(keys, count) };
    let mut out = Vec::with_capacity(count);

    for key_ptr in key_ptrs {
        if key_ptr.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }
        let key = unsafe { &*(*key_ptr as *const PQSignatureSchemePublicKeyInner) };
        out.push((*key.inner).clone());
    }

    Ok(out)
}

fn collect_signatures(
    signatures: *const *const PQSignature,
    count: usize,
) -> Result<Vec<SignatureType>, PQSigningError> {
    if signatures.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let sig_ptrs = unsafe { slice::from_raw_parts(signatures, count) };
    let mut out = Vec::with_capacity(count);

    for sig_ptr in sig_ptrs {
        if sig_ptr.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }
        let sig = unsafe { &*(*sig_ptr as *const PQSignatureInner) };
        out.push((*sig.inner).clone());
    }

    Ok(out)
}

/// Aggregate XMSS signatures into a serialized proof.
///
/// # Parameters
/// - `pubkeys`: array of public key pointers
/// - `signatures`: array of signature pointers
/// - `count`: number of entries in pubkeys/signatures
/// - `message`: pointer to message (32 bytes)
/// - `message_len`: length of message (must be 32)
/// - `epoch`: signature epoch
/// - `buffer`: output buffer
/// - `buffer_len`: output buffer size
/// - `written_len`: number of bytes written (output)
///
/// # Returns
/// Error code
#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    signatures: *const *const PQSignature,
    count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if pubkeys.is_null() || signatures.is_null() || message.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if message_len != MESSAGE_LENGTH {
        return PQSigningError::InvalidMessageLength;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return PQSigningError::InvalidEpoch,
    };

    let pub_keys = match collect_public_keys(pubkeys, count) {
        Ok(keys) => keys,
        Err(err) => return err,
    };
    let sigs = match collect_signatures(signatures, count) {
        Ok(sigs) => sigs,
        Err(err) => return err,
    };

    let message_slice = slice::from_raw_parts(message, message_len);
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    let agg_signature = match xmss_aggregate_signatures(&pub_keys, &sigs, &message_array, epoch32) {
        Ok(sig) => sig,
        Err(XmssAggregateError::WrongSignatureCount) => return PQSigningError::UnknownError,
        Err(XmssAggregateError::InvalidSigature) => return PQSigningError::UnknownError,
    };

    let encoded = serialize_agg_signature(&agg_signature);
    if encoded.len() > buffer_len {
        *written_len = encoded.len();
        return PQSigningError::UnknownError;
    }

    let out_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    out_slice[..encoded.len()].copy_from_slice(&encoded);
    *written_len = encoded.len();

    PQSigningError::Success
}

/// Verify an aggregated XMSS signature proof.
///
/// # Parameters
/// - `pubkeys`: array of public key pointers
/// - `count`: number of public keys
/// - `message`: pointer to message (32 bytes)
/// - `message_len`: length of message (must be 32)
/// - `agg_bytes`: pointer to serialized aggregated signature bytes
/// - `agg_len`: length of aggregated signature bytes
/// - `epoch`: signature epoch
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
#[no_mangle]
pub unsafe extern "C" fn pq_verify_aggregated_signatures(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    count: usize,
    message: *const u8,
    message_len: usize,
    agg_bytes: *const u8,
    agg_len: usize,
    epoch: u64,
) -> c_int {
    if pubkeys.is_null() || message.is_null() || agg_bytes.is_null() {
        return -1;
    }

    if message_len != MESSAGE_LENGTH {
        return -2;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return -3,
    };

    let pub_keys = match collect_public_keys(pubkeys, count) {
        Ok(keys) => keys,
        Err(_) => return -4,
    };

    let message_slice = slice::from_raw_parts(message, message_len);
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    let agg_slice = slice::from_raw_parts(agg_bytes, agg_len);
    let agg_signature = match deserialize_agg_signature(agg_slice) {
        Ok(sig) => sig,
        Err(_) => return -5,
    };

    match xmss_verify_aggregated_signatures(&pub_keys, &message_array, &agg_signature, epoch32) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_key_gen_sign_verify() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();

            let result = pq_key_gen(0, 100, &mut pk, &mut sk);
            assert_eq!(result, PQSigningError::Success);
            assert!(!pk.is_null());
            assert!(!sk.is_null());

            let message = [0u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            let sign_result = pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);
            assert_eq!(sign_result, PQSigningError::Success);
            assert!(!signature.is_null());

            let verify_result = pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(verify_result, 1);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }
}
