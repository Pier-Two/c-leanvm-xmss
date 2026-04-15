use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use lean_multisig::AggregatedXMSS;
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey, SigningError};
use leansig_wrapper::{LeanSigScheme, MESSAGE_LENGTH, XmssPublicKey, XmssSecretKey, XmssSignature};
use ssz::{Decode, Encode};

pub const PUBLIC_KEY_SIZE: usize = 52;
#[cfg(feature = "test-config")]
const ACTIVE_SIGNATURE_SIZE: usize = 424;
#[cfg(not(feature = "test-config"))]
const ACTIVE_SIGNATURE_SIZE: usize = 2536;
const SIGNATURE_SIZE: usize = ACTIVE_SIGNATURE_SIZE;

const DEFAULT_LOG_INV_RATE: usize = 2;
const LEGACY_SIGNATURE_SIZE: usize = 3112;

type PublicKeyType = XmssPublicKey;
type SecretKeyType = XmssSecretKey;
type SignatureType = XmssSignature;

#[repr(C)]
pub struct PQSignatureSchemeSecretKey {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQSignatureSchemePublicKey {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQSignature {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQRawXmssSignature {
    pub pubkey: *const PQSignatureSchemePublicKey,
    pub signature: *const PQSignature,
}

#[repr(C)]
pub struct PQAggregatedSignatureChild {
    pub pubkeys: *const *const PQSignatureSchemePublicKey,
    pub pubkey_count: usize,
    pub agg_bytes: *const u8,
    pub agg_len: usize,
}

struct PQSignatureSchemeSecretKeyInner {
    inner: Box<SecretKeyType>,
}

struct PQSignatureSchemePublicKeyInner {
    inner: Box<PublicKeyType>,
}

struct PQSignatureInner {
    inner: Box<SignatureType>,
}

#[repr(C)]
pub struct PQRange {
    pub start: u64,
    pub end: u64,
}

impl From<std::ops::Range<u64>> for PQRange {
    fn from(range: std::ops::Range<u64>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PQSigningError {
    Success = 0,
    EncodingAttemptsExceeded = 1,
    InvalidPointer = 2,
    InvalidMessageLength = 3,
    InvalidEpoch = 4,
    UnknownError = 99,
}

fn epoch_to_u32(epoch: u64) -> Result<u32, PQSigningError> {
    u32::try_from(epoch).map_err(|_| PQSigningError::InvalidEpoch)
}

unsafe fn message_from_ptr(
    message: *const u8,
    message_len: usize,
) -> Result<[u8; MESSAGE_LENGTH], PQSigningError> {
    if message.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }
    if message_len != MESSAGE_LENGTH {
        return Err(PQSigningError::InvalidMessageLength);
    }

    let message_slice = slice::from_raw_parts(message, message_len);
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);
    Ok(message_array)
}

fn serialized_proof_from_bytes(bytes: &[u8]) -> Result<AggregatedXMSS, PQSigningError> {
    AggregatedXMSS::deserialize(bytes).ok_or(PQSigningError::UnknownError)
}

fn normalize_signature_bytes(bytes: &[u8]) -> Result<&[u8], PQSigningError> {
    if bytes.len() == SIGNATURE_SIZE {
        return Ok(bytes);
    }

    if bytes.len() == LEGACY_SIGNATURE_SIZE {
        let (signature_bytes, trailing_padding) = bytes.split_at(SIGNATURE_SIZE);
        if trailing_padding.iter().all(|byte| *byte == 0) {
            return Ok(signature_bytes);
        }
    }

    Err(PQSigningError::UnknownError)
}

unsafe fn write_bytes_to_buffer(
    bytes: &[u8],
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError;
    }

    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

fn collect_public_keys(
    keys: *const *const PQSignatureSchemePublicKey,
    count: usize,
) -> Result<Vec<PublicKeyType>, PQSigningError> {
    if count == 0 {
        return Ok(Vec::new());
    }
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
    if count == 0 {
        return Ok(Vec::new());
    }
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

fn collect_raw_xmss_inputs(
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<(PublicKeyType, SignatureType)>, PQSigningError> {
    if raw_xmss_count == 0 {
        return Ok(Vec::new());
    }
    if raw_xmss.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let raw_inputs = unsafe { slice::from_raw_parts(raw_xmss, raw_xmss_count) };
    let mut out = Vec::with_capacity(raw_xmss_count);

    for raw_input in raw_inputs {
        if raw_input.pubkey.is_null() || raw_input.signature.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let public_key = unsafe { &*(raw_input.pubkey as *const PQSignatureSchemePublicKeyInner) };
        let signature = unsafe { &*(raw_input.signature as *const PQSignatureInner) };
        let public_key = (*public_key.inner).clone();
        let signature = (*signature.inner).clone();

        if !LeanSigScheme::verify(&public_key, epoch, message, &signature) {
            return Err(PQSigningError::UnknownError);
        }

        out.push((public_key, signature));
    }

    Ok(out)
}

fn collect_child_aggregations(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<(Vec<PublicKeyType>, AggregatedXMSS)>, PQSigningError> {
    if child_count == 0 {
        return Ok(Vec::new());
    }
    if children.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let child_inputs = unsafe { slice::from_raw_parts(children, child_count) };
    let mut out = Vec::with_capacity(child_count);

    for child in child_inputs {
        if child.agg_bytes.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let pubkeys = collect_public_keys(child.pubkeys, child.pubkey_count)?;
        let proof_bytes = unsafe { slice::from_raw_parts(child.agg_bytes, child.agg_len) };
        let aggregated = serialized_proof_from_bytes(proof_bytes)?;

        if lean_multisig::xmss_verify_aggregation(pubkeys.clone(), &aggregated, message, epoch).is_err() {
            return Err(PQSigningError::UnknownError);
        }

        out.push((pubkeys, aggregated));
    }

    Ok(out)
}

unsafe fn aggregate_signatures_impl(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }
    if (child_count > 0 && children.is_null())
        || (raw_xmss_count > 0 && raw_xmss.is_null())
        || message.is_null()
    {
        return PQSigningError::InvalidPointer;
    }
    if child_count == 0 && raw_xmss_count == 0 {
        return PQSigningError::UnknownError;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let raw_xmss_inputs = match collect_raw_xmss_inputs(raw_xmss, raw_xmss_count, &message_array, epoch32) {
        Ok(raw_xmss_inputs) => raw_xmss_inputs,
        Err(err) => return err,
    };
    let child_inputs = match collect_child_aggregations(children, child_count, &message_array, epoch32) {
        Ok(child_inputs) => child_inputs,
        Err(err) => return err,
    };

    let mut child_pubkeys = Vec::with_capacity(child_inputs.len());
    let mut child_aggregations = Vec::with_capacity(child_inputs.len());
    for (pubkeys, aggregation) in child_inputs {
        child_pubkeys.push(pubkeys.into_boxed_slice());
        child_aggregations.push(aggregation);
    }
    let child_refs: Vec<(&[PublicKeyType], AggregatedXMSS)> = child_pubkeys
        .iter()
        .zip(child_aggregations.into_iter())
        .map(|(pubkeys, aggregation)| (&pubkeys[..], aggregation))
        .collect();

    let aggregated = match catch_unwind(AssertUnwindSafe(|| {
        lean_multisig::xmss_aggregate(&child_refs, raw_xmss_inputs, &message_array, epoch32, log_inv_rate)
    })) {
        Ok((_, aggregated)) => aggregated,
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&aggregated.serialize(), buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_free(key: *mut PQSignatureSchemeSecretKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemeSecretKeyInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_free(key: *mut PQSignatureSchemePublicKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemePublicKeyInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_free(signature: *mut PQSignature) {
    if !signature.is_null() {
        let _ = Box::from_raw(signature as *mut PQSignatureInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

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

#[no_mangle]
pub unsafe extern "C" fn pq_advance_preparation(key: *mut PQSignatureSchemeSecretKey) {
    if key.is_null() {
        return;
    }

    let key = &mut *(key as *mut PQSignatureSchemeSecretKeyInner);
    key.inner.advance_preparation();
}

#[no_mangle]
pub extern "C" fn pq_get_lifetime() -> u64 {
    LeanSigScheme::LIFETIME
}

#[no_mangle]
pub extern "C" fn pq_get_signature_size() -> usize {
    SIGNATURE_SIZE
}

#[no_mangle]
pub extern "C" fn pq_get_public_key_size() -> usize {
    PUBLIC_KEY_SIZE
}

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

    let Some(end_epoch) = activation_epoch.checked_add(num_active_epochs) else {
        return PQSigningError::InvalidEpoch;
    };
    if end_epoch > LeanSigScheme::LIFETIME as usize {
        return PQSigningError::InvalidEpoch;
    }

    let mut rng = rand::rng();
    let (pk, sk) = match catch_unwind(AssertUnwindSafe(|| {
        LeanSigScheme::key_gen(&mut rng, activation_epoch, num_active_epochs)
    })) {
        Ok(keys) => keys,
        Err(_) => return PQSigningError::UnknownError,
    };

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

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);

    if !sk.inner.get_activation_interval().contains(&epoch) || !sk.inner.get_prepared_interval().contains(&epoch) {
        return PQSigningError::InvalidEpoch;
    }

    let signature = match catch_unwind(AssertUnwindSafe(|| {
        LeanSigScheme::sign(&sk.inner, epoch32, &message_array)
    })) {
        Ok(Ok(signature)) => signature,
        Ok(Err(SigningError::EncodingAttemptsExceeded { .. })) => {
            return PQSigningError::EncodingAttemptsExceeded;
        }
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

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

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    let signature = &*(signature as *const PQSignatureInner);

    if LeanSigScheme::verify(&pk.inner, epoch32, &message_array, &signature.inner) {
        1
    } else {
        0
    }
}

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
    if pubkey_len != PUBLIC_KEY_SIZE {
        return -7;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };

    let pubkey_bytes = slice::from_raw_parts(pubkey_bytes, pubkey_len);
    let signature_bytes = slice::from_raw_parts(signature_bytes, signature_len);
    let signature_bytes = match normalize_signature_bytes(signature_bytes) {
        Ok(signature_bytes) => signature_bytes,
        Err(_) => return -8,
    };

    let public_key = match PublicKeyType::from_ssz_bytes(pubkey_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return -5,
    };
    let signature = match SignatureType::from_ssz_bytes(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return -6,
    };

    if LeanSigScheme::verify(&public_key, epoch32, &message_array, &signature) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn pq_error_description(error: PQSigningError) -> *mut c_char {
    let description = match error {
        PQSigningError::Success => "Success",
        PQSigningError::EncodingAttemptsExceeded => "Encoding attempts exceeded",
        PQSigningError::InvalidPointer => "Invalid pointer",
        PQSigningError::InvalidMessageLength => "Invalid message length",
        PQSigningError::InvalidEpoch => "Invalid epoch",
        PQSigningError::UnknownError => "Unknown error",
    };

    CString::new(description).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_serialize(
    sk: *const PQSignatureSchemeSecretKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if sk.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);
    write_bytes_to_buffer(&sk.inner.as_ssz_bytes(), buffer, buffer_len, written_len)
}

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
    let secret_key = match SecretKeyType::from_ssz_bytes(buffer_slice) {
        Ok(secret_key) => secret_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let secret_key_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(secret_key),
    });
    *sk_out = Box::into_raw(secret_key_wrapper) as *mut PQSignatureSchemeSecretKey;
    PQSigningError::Success
}

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
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let secret_key = match serde_json::from_str::<SecretKeyType>(json_str) {
        Ok(secret_key) => secret_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let secret_key_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(secret_key),
    });
    *sk_out = Box::into_raw(secret_key_wrapper) as *mut PQSignatureSchemeSecretKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_serialize(
    pk: *const PQSignatureSchemePublicKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if pk.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    write_bytes_to_buffer(&pk.inner.as_ssz_bytes(), buffer, buffer_len, written_len)
}

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
    let public_key = match PublicKeyType::from_ssz_bytes(buffer_slice) {
        Ok(public_key) => public_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let public_key_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(public_key),
    });
    *pk_out = Box::into_raw(public_key_wrapper) as *mut PQSignatureSchemePublicKey;
    PQSigningError::Success
}

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
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let public_key = match serde_json::from_str::<PublicKeyType>(json_str) {
        Ok(public_key) => public_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let public_key_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(public_key),
    });
    *pk_out = Box::into_raw(public_key_wrapper) as *mut PQSignatureSchemePublicKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_serialize(
    signature: *const PQSignature,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if signature.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let signature = &*(signature as *const PQSignatureInner);
    write_bytes_to_buffer(&signature.inner.as_ssz_bytes(), buffer, buffer_len, written_len)
}

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
    let signature_bytes = match normalize_signature_bytes(buffer_slice) {
        Ok(signature_bytes) => signature_bytes,
        Err(err) => return err,
    };
    let signature = match SignatureType::from_ssz_bytes(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_from_json(
    json: *const u8,
    json_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if json.is_null() || signature_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let signature = match serde_json::from_str::<SignatureType>(json_str) {
        Ok(signature) => signature,
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_prover() {
    let _ = catch_unwind(AssertUnwindSafe(lean_multisig::setup_prover));
}

#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_verifier() {
    let _ = catch_unwind(AssertUnwindSafe(lean_multisig::setup_verifier));
}

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
    if count == 0 {
        return PQSigningError::UnknownError;
    }

    if pubkeys.is_null() || signatures.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let pubkeys = match collect_public_keys(pubkeys, count) {
        Ok(pubkeys) => pubkeys,
        Err(err) => return err,
    };
    let signatures = match collect_signatures(signatures, count) {
        Ok(signatures) => signatures,
        Err(err) => return err,
    };
    let mut raw_xmss = Vec::with_capacity(count);
    for (pubkey, signature) in pubkeys.into_iter().zip(signatures.into_iter()) {
        if !LeanSigScheme::verify(&pubkey, epoch32, &message_array, &signature) {
            return PQSigningError::UnknownError;
        }
        raw_xmss.push((pubkey, signature));
    }

    let no_children: [(&[PublicKeyType], AggregatedXMSS); 0] = [];
    let aggregated = match catch_unwind(AssertUnwindSafe(|| {
        lean_multisig::xmss_aggregate(&no_children, raw_xmss, &message_array, epoch32, DEFAULT_LOG_INV_RATE)
    })) {
        Ok((_, aggregated)) => aggregated,
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&aggregated.serialize(), buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures_recursive(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    aggregate_signatures_impl(
        children,
        child_count,
        raw_xmss,
        raw_xmss_count,
        message,
        message_len,
        epoch,
        log_inv_rate,
        buffer,
        buffer_len,
        written_len,
    )
}

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

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };
    let pubkeys = match collect_public_keys(pubkeys, count) {
        Ok(pubkeys) => pubkeys,
        Err(_) => return -4,
    };
    let agg_bytes = slice::from_raw_parts(agg_bytes, agg_len);
    let aggregated = match serialized_proof_from_bytes(agg_bytes) {
        Ok(aggregated) => aggregated,
        Err(_) => return -5,
    };

    match lean_multisig::xmss_verify_aggregation(pubkeys, &aggregated, &message_array, epoch32) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_exported_devnet4_sizes() {
        assert_eq!(PUBLIC_KEY_SIZE, 52);
        #[cfg(feature = "test-config")]
        assert_eq!(SIGNATURE_SIZE, 424);
        #[cfg(not(feature = "test-config"))]
        assert_eq!(SIGNATURE_SIZE, 2536);
        assert_eq!(pq_get_public_key_size(), PUBLIC_KEY_SIZE);
        assert_eq!(pq_get_signature_size(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_normalize_signature_bytes_accepts_legacy_zero_padding() {
        let mut padded = vec![0u8; LEGACY_SIGNATURE_SIZE];
        padded[..SIGNATURE_SIZE].fill(0xAB);
        assert_eq!(normalize_signature_bytes(&padded).unwrap(), &padded[..SIGNATURE_SIZE]);
    }

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
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

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
    fn test_signature_size_matches_devnet4_encoding() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            assert_eq!(pq_key_gen(0, 100, &mut pk, &mut sk), PQSigningError::Success);

            let message = [7u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                PQSigningError::Success
            );

            let mut serialized = vec![0u8; SIGNATURE_SIZE];
            let mut written = 0usize;
            assert_eq!(
                pq_signature_serialize(signature, serialized.as_mut_ptr(), serialized.len(), &mut written),
                PQSigningError::Success
            );
            assert_eq!(written, SIGNATURE_SIZE);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
    fn test_signature_deserialize_accepts_legacy_zero_padding() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            assert_eq!(pq_key_gen(0, 100, &mut pk, &mut sk), PQSigningError::Success);

            let message = [3u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                PQSigningError::Success
            );

            let mut serialized = vec![0u8; LEGACY_SIGNATURE_SIZE];
            let mut written = 0usize;
            assert_eq!(
                pq_signature_serialize(signature, serialized.as_mut_ptr(), SIGNATURE_SIZE, &mut written),
                PQSigningError::Success
            );
            assert_eq!(written, SIGNATURE_SIZE);

            let mut deserialized: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_signature_deserialize(serialized.as_ptr(), serialized.len(), &mut deserialized),
                PQSigningError::Success
            );
            assert_eq!(pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, deserialized), 1);

            let mut pubkey_bytes = [0u8; PUBLIC_KEY_SIZE];
            let mut pubkey_written = 0usize;
            assert_eq!(
                pq_public_key_serialize(pk, pubkey_bytes.as_mut_ptr(), pubkey_bytes.len(), &mut pubkey_written),
                PQSigningError::Success
            );
            assert_eq!(pubkey_written, PUBLIC_KEY_SIZE);
            assert_eq!(
                pq_verify_ssz(
                    pubkey_bytes.as_ptr(),
                    PUBLIC_KEY_SIZE,
                    10,
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    serialized.as_ptr(),
                    serialized.len(),
                ),
                1
            );

            pq_signature_free(deserialized);
            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    #[ignore = "expensive aggregation proof generation"]
    fn test_recursive_aggregation_smoke() {
        unsafe {
            pq_xmss_aggregation_setup_prover();

            let message = [9u8; MESSAGE_LENGTH];
            let mut pubkeys = Vec::new();
            let mut secrets = Vec::new();
            let mut signatures = Vec::new();

            for _ in 0..3 {
                let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
                let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
                assert_eq!(pq_key_gen(0, 100, &mut pk, &mut sk), PQSigningError::Success);

                let mut signature: *mut PQSignature = ptr::null_mut();
                assert_eq!(
                    pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                    PQSigningError::Success
                );

                pubkeys.push(pk);
                secrets.push(sk);
                signatures.push(signature);
            }

            let child_one_pubkeys = [pubkeys[0] as *const PQSignatureSchemePublicKey];
            let child_one_signatures = [signatures[0] as *const PQSignature];
            let mut child_one_bytes = vec![0u8; 512 * 1024];
            let mut child_one_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures(
                    child_one_pubkeys.as_ptr(),
                    child_one_signatures.as_ptr(),
                    child_one_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    child_one_bytes.as_mut_ptr(),
                    child_one_bytes.len(),
                    &mut child_one_written,
                ),
                PQSigningError::Success
            );
            child_one_bytes.truncate(child_one_written);

            let child_two_pubkeys = [pubkeys[1] as *const PQSignatureSchemePublicKey];
            let child_two_signatures = [signatures[1] as *const PQSignature];
            let mut child_two_bytes = vec![0u8; 512 * 1024];
            let mut child_two_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures(
                    child_two_pubkeys.as_ptr(),
                    child_two_signatures.as_ptr(),
                    child_two_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    child_two_bytes.as_mut_ptr(),
                    child_two_bytes.len(),
                    &mut child_two_written,
                ),
                PQSigningError::Success
            );
            child_two_bytes.truncate(child_two_written);

            let children = [
                PQAggregatedSignatureChild {
                    pubkeys: child_one_pubkeys.as_ptr(),
                    pubkey_count: child_one_pubkeys.len(),
                    agg_bytes: child_one_bytes.as_ptr(),
                    agg_len: child_one_bytes.len(),
                },
                PQAggregatedSignatureChild {
                    pubkeys: child_two_pubkeys.as_ptr(),
                    pubkey_count: child_two_pubkeys.len(),
                    agg_bytes: child_two_bytes.as_ptr(),
                    agg_len: child_two_bytes.len(),
                },
            ];
            let raw_xmss = [PQRawXmssSignature {
                pubkey: pubkeys[2] as *const PQSignatureSchemePublicKey,
                signature: signatures[2] as *const PQSignature,
            }];
            let final_pubkeys = [
                pubkeys[0] as *const PQSignatureSchemePublicKey,
                pubkeys[1] as *const PQSignatureSchemePublicKey,
                pubkeys[2] as *const PQSignatureSchemePublicKey,
            ];

            let mut final_bytes = vec![0u8; 1024 * 1024];
            let mut final_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures_recursive(
                    children.as_ptr(),
                    children.len(),
                    raw_xmss.as_ptr(),
                    raw_xmss.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    DEFAULT_LOG_INV_RATE,
                    final_bytes.as_mut_ptr(),
                    final_bytes.len(),
                    &mut final_written,
                ),
                PQSigningError::Success
            );
            final_bytes.truncate(final_written);

            pq_xmss_aggregation_setup_verifier();
            assert_eq!(
                pq_verify_aggregated_signatures(
                    final_pubkeys.as_ptr(),
                    final_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    final_bytes.as_ptr(),
                    final_bytes.len(),
                    10,
                ),
                1
            );

            for signature in signatures {
                pq_signature_free(signature);
            }
            for pubkey in pubkeys {
                pq_public_key_free(pubkey);
            }
            for secret in secrets {
                pq_secret_key_free(secret);
            }
        }
    }
}
