//! Verify a WebAuthn direct attestation against Yubico's published CAs.
//!
//! The certificates are the PEM blocks from
//! <https://developers.yubico.com/PKI/yubico-ca-certs.txt> and
//! <https://developers.yubico.com/PKI/yubico-intermediate.pem>.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use der::{Decode, DecodePem, Encode};
use rsa::pkcs1::DecodeRsaPublicKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use yubikit::cbor;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{
    AuthenticatorOptions, Ctap2Error, Ctap2Session, CtapStatus, PublicKeyCredentialRpEntity,
};
use yubikit::webauthn::types::{
    PublicKeyCredentialParameters, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
};

use crate::rpc::SignalFn;

use crate::error::{RpcError, RpcResponse};

const ROOTS_PEM: &str = include_str!("../certs/yubico-ca-certs.txt");
const INTERMEDIATES_PEM: &str = include_str!("../certs/yubico-intermediate.pem");

const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const RSA_KEY: &str = "1.2.840.113549.1.1.1";
const EC_KEY: &str = "1.2.840.10045.2.1";

const DEVICE_TYPE: &str = "1.3.6.1.4.1.41482.2";
const FIRMWARE: &str = "1.3.6.1.4.1.41482.13.1";
const SERIAL: &str = "1.3.6.1.4.1.45724.1.1.2";

pub fn check(
    params: &Value,
    signal: SignalFn,
    cancel: &AtomicBool,
) -> Result<RpcResponse, RpcError> {
    let result = if params
        .get("attestation_object")
        .and_then(Value::as_str)
        .is_some()
    {
        let attestation = required_str(params, "attestation_object")?;
        let client_data = required_str(params, "client_data")?;
        verify(attestation, client_data)
    } else {
        read_from_key(signal, cancel)
    };
    match result {
        Ok(body) => Ok(RpcResponse::new(body)),
        Err(message) => Err(RpcError::new("genuine-failed", message)),
    }
}

fn read_from_key(signal: SignalFn, cancel: &AtomicBool) -> Result<Value, String> {
    let mut devices = crate::monitor::devices();
    let Some((device, _)) = devices.pop() else {
        return Err("Insert a YubiKey to verify it.".into());
    };
    let connection = device.open_fido().map_err(|_| {
        "Could not open FIDO on this YubiKey. Close anything else using it, then try again."
            .to_string()
    })?;
    let ctap = CtapSession::new_fido(connection)
        .map_err(|(error, _)| format!("Could not open FIDO on this YubiKey: {error}"))?;
    let mut session = Ctap2Session::new(ctap)
        .map_err(|(error, _)| format!("This YubiKey does not support FIDO2: {error}"))?;

    let mut challenge = [0u8; 32];
    let mut user_id = [0u8; 16];
    getrandom::fill(&mut challenge).map_err(|_| "Could not generate a challenge.".to_string())?;
    getrandom::fill(&mut user_id).map_err(|_| "Could not generate a challenge.".to_string())?;
    let client_bytes = serde_json::to_vec(&json!({
        "type": "webauthn.create",
        "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        "origin": "http://localhost",
    }))
    .map_err(|_| "Could not build the client data.".to_string())?;
    let client_hash = Sha256::digest(&client_bytes);
    let rp = PublicKeyCredentialRpEntity {
        id: "localhost".into(),
        name: Some("Yubico Authenticator".into()),
    };
    let user = PublicKeyCredentialUserEntity {
        id: user_id.to_vec(),
        name: Some("genuine-check".into()),
        display_name: Some("Genuine check".into()),
    };
    let params = [PublicKeyCredentialParameters {
        type_: PublicKeyCredentialType::PublicKey,
        alg: -7,
    }];
    let options = AuthenticatorOptions {
        rk: Some(false),
        uv: Some(false),
        up: None,
    };
    signal("touch", json!({}));
    let mut prompted = false;
    let mut on_keepalive = |status: u8| {
        if status == 0x02 && !prompted {
            prompted = true;
            signal("touch", json!({}));
        }
    };
    let is_cancelled = || cancel.load(Ordering::Relaxed);
    let response = session
        .make_credential(
            &client_hash,
            &rp,
            &user,
            &params,
            None,
            None,
            Some(&options),
            None,
            None,
            None,
            Some(&mut on_keepalive),
            Some(&is_cancelled),
        )
        .map_err(ctap_message)?;
    let attestation = cbor::encode(&cbor::Value::Map(vec![
        (
            cbor::Value::Text("fmt".into()),
            cbor::Value::Text(response.fmt),
        ),
        (
            cbor::Value::Text("authData".into()),
            cbor::Value::Bytes(response.auth_data),
        ),
        (cbor::Value::Text("attStmt".into()), response.att_stmt),
    ]));
    verify_bytes(&attestation, &client_bytes)
}

fn ctap_message<E>(error: Ctap2Error<E>) -> String
where
    E: std::error::Error + Send + Sync + 'static,
{
    match error {
        Ctap2Error::StatusError(CtapStatus::PuatRequired) => {
            "This YubiKey requires its FIDO PIN before it will share an attestation certificate."
                .into()
        }
        Ctap2Error::StatusError(CtapStatus::UserActionTimeout) => {
            "The YubiKey was not touched in time.".into()
        }
        Ctap2Error::StatusError(CtapStatus::KeepaliveCancel) => "The check was cancelled.".into(),
        other => format!("Could not read the attestation certificate: {other}"),
    }
}

fn required_str<'a>(params: &'a Value, name: &str) -> Result<&'a str, RpcError> {
    params
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RpcError::new("invalid-params", format!("Missing {name}")))
}

fn verify(attestation_b64: &str, client_b64: &str) -> Result<Value, String> {
    verify_bytes(&decode_b64(attestation_b64)?, &decode_b64(client_b64)?)
}

fn verify_bytes(attestation: &[u8], client_bytes: &[u8]) -> Result<Value, String> {
    let client: Value = serde_json::from_slice(&client_bytes)
        .map_err(|_| "The client data is not JSON.".to_string())?;
    if client["type"].as_str() != Some("webauthn.create") {
        return Err("The ceremony was not a credential creation.".into());
    }
    let origin = client["origin"]
        .as_str()
        .ok_or("The client data has no origin.")?;
    let rp_id = relying_party(origin)?;
    let client_hash = Sha256::digest(&client_bytes);

    let object = cbor::decode(&attestation).map_err(|_| "The attestation is not CBOR.")?;
    let cbor::Value::Map(ref entries) = object else {
        return Err("The attestation object is not a CBOR map.".into());
    };
    let format = text_field(&entries, "fmt")?;
    let auth_data = bytes_field(&entries, "authData")?;
    let statement = map_field(&entries, "attStmt")?;
    if auth_data.len() < 37 {
        return Err("The authenticator data is too short.".into());
    }
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != rp_hash[..] {
        return Err("The attestation was created for a different site.".into());
    }

    if format == "none" {
        return Ok(json!({
            "genuine": false,
            "format": format,
            "message": "The browser did not include an attestation certificate.",
        }));
    }

    let (signature, certificates, signed) = match format.as_str() {
        "packed" => packed(&statement, auth_data, &client_hash)?,
        "fido-u2f" => fido_u2f(&statement, auth_data, &client_hash)?,
        other => return Err(format!("Unsupported attestation format {other}.")),
    };
    let leaf = certificates
        .first()
        .ok_or("The attestation has no certificate.")?;
    verify_statement(
        leaf,
        statement_alg(&statement, &format)?,
        &signed,
        &signature,
    )?;
    let genuine = chains_to_yubico(leaf, &certificates[1..]);
    let details = cert_details(leaf);
    if genuine {
        Ok(json!({
            "genuine": true,
            "format": format,
            "message": "This attestation certificate chains to a Yubico CA.",
            "subject": details.subject,
            "device": details.device,
            "firmware": details.firmware,
            "serial": details.serial,
        }))
    } else {
        Ok(json!({
            "genuine": false,
            "format": format,
            "message": "The attestation certificate does not chain to a Yubico CA.",
            "subject": details.subject,
            "device": details.device,
            "firmware": details.firmware,
            "serial": details.serial,
        }))
    }
}

fn relying_party(origin: &str) -> Result<String, String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or("The ceremony origin is not a web origin.")?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => host_port,
    };
    if host == "127.0.0.1" || host == "localhost" {
        Ok(host.to_string())
    } else {
        Err("This check only accepts an attestation created on this page.".into())
    }
}

fn packed(
    statement: &[(cbor::Value, cbor::Value)],
    auth_data: &[u8],
    client_hash: &[u8],
) -> Result<(Vec<u8>, Vec<Certificate>, Vec<u8>), String> {
    let signature = bytes_field(statement, "sig")?.to_vec();
    let certificates = x5c(statement)?;
    let mut signed = Vec::with_capacity(auth_data.len() + client_hash.len());
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(client_hash);
    Ok((signature, certificates, signed))
}

fn fido_u2f(
    statement: &[(cbor::Value, cbor::Value)],
    auth_data: &[u8],
    client_hash: &[u8],
) -> Result<(Vec<u8>, Vec<Certificate>, Vec<u8>), String> {
    let signature = bytes_field(statement, "sig")?.to_vec();
    let certificates = x5c(statement)?;
    if auth_data.len() < 55 || auth_data[32] & 0x40 == 0 {
        return Err("The U2F attestation has no credential data.".into());
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_end = 55 + cred_len;
    if auth_data.len() < cred_end {
        return Err("The credential id is truncated.".into());
    }
    let public_key = uncompressed_point(&auth_data[cred_end..])?;
    let mut signed = Vec::with_capacity(1 + 32 + 32 + cred_len + public_key.len());
    signed.push(0);
    signed.extend_from_slice(&auth_data[..32]);
    signed.extend_from_slice(client_hash);
    signed.extend_from_slice(&auth_data[55..cred_end]);
    signed.extend_from_slice(&public_key);
    Ok((signature, certificates, signed))
}

fn statement_alg(statement: &[(cbor::Value, cbor::Value)], format: &str) -> Result<i64, String> {
    if format == "fido-u2f" {
        return Ok(-7);
    }
    match field(statement, &cbor::Value::Text("alg".into())) {
        Some(cbor::Value::Int(alg)) => Ok(*alg),
        _ => Err("The packed attestation has no algorithm.".into()),
    }
}

fn x5c(statement: &[(cbor::Value, cbor::Value)]) -> Result<Vec<Certificate>, String> {
    let Some(cbor::Value::Array(certs)) = field(statement, &cbor::Value::Text("x5c".into())) else {
        return Err("The attestation has no certificate chain.".into());
    };
    certs
        .iter()
        .map(|cert| match cert {
            cbor::Value::Bytes(bytes) => Certificate::from_der(bytes)
                .map_err(|_| "A certificate in the attestation could not be parsed.".to_string()),
            _ => Err("A certificate in the attestation is not a byte string.".into()),
        })
        .collect()
}

fn uncompressed_point(cbor_key: &[u8]) -> Result<Vec<u8>, String> {
    let (value, _) = cbor::decode_from(cbor_key)
        .map_err(|_| "The credential public key could not be parsed.")?;
    let cbor::Value::Map(ref entries) = value else {
        return Err("The credential public key is not a COSE key.".into());
    };
    let x = bytes_at(&entries, -2)?;
    let y = bytes_at(&entries, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("The credential public key is not P-256.".into());
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
}

fn verify_statement(
    leaf: &Certificate,
    alg: i64,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = &leaf.tbs_certificate.subject_public_key_info;
    match alg {
        -7 => verify_p256(key, message, signature),
        -257 => verify_rsa(key, RSA_SHA256, message, signature),
        other => Err(format!("Unsupported attestation algorithm {other}.")),
    }
}

fn chains_to_yubico(leaf: &Certificate, extra: &[Certificate]) -> bool {
    let mut pool = bundle().to_vec();
    pool.extend_from_slice(extra);
    let mut current = leaf.clone();
    for _ in 0..8 {
        let Some(parent) = find_signer(&current, &pool).cloned() else {
            return false;
        };
        if is_trusted_root(&parent) {
            return true;
        }
        if same_name_and_key(&parent, &current) {
            return false;
        }
        current = parent;
    }
    false
}

fn is_trusted_root(cert: &Certificate) -> bool {
    let Some(subject) = name_bytes(&cert.tbs_certificate.subject).ok() else {
        return false;
    };
    if name_bytes(&cert.tbs_certificate.issuer).ok().as_deref() != Some(subject.as_slice()) {
        return false;
    }
    if !signature_valid(cert, cert) {
        return false;
    }
    let key = bit_bytes(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key,
    );
    bundle().iter().any(|root| {
        name_bytes(&root.tbs_certificate.subject).ok().as_deref() == Some(subject.as_slice())
            && bit_bytes(
                &root
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key,
            ) == key
    })
}

fn same_name_and_key(left: &Certificate, right: &Certificate) -> bool {
    name_bytes(&left.tbs_certificate.subject).ok()
        == name_bytes(&right.tbs_certificate.subject).ok()
        && bit_bytes(
            &left
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key,
        ) == bit_bytes(
            &right
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key,
        )
}

fn find_signer<'a>(child: &Certificate, candidates: &'a [Certificate]) -> Option<&'a Certificate> {
    let issuer = name_bytes(&child.tbs_certificate.issuer).ok()?;
    candidates.iter().find(|candidate| {
        name_bytes(&candidate.tbs_certificate.subject)
            .ok()
            .as_deref()
            == Some(issuer.as_slice())
            && signature_valid(candidate, child)
    })
}

fn signature_valid(issuer: &Certificate, child: &Certificate) -> bool {
    let Ok(message) = child.tbs_certificate.to_der() else {
        return false;
    };
    let signature = bit_bytes(&child.signature);
    verify_key(
        &issuer.tbs_certificate.subject_public_key_info,
        &child.signature_algorithm.oid.to_string(),
        &message,
        signature,
    )
    .is_ok()
}

fn verify_key(
    key: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    algorithm: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    match algorithm {
        RSA_SHA256 | RSA_SHA384 | RSA_SHA512 => verify_rsa(key, algorithm, message, signature),
        ECDSA_SHA256 => verify_p256(key, message, signature),
        other => Err(format!("Unsupported signature algorithm {other}.")),
    }
}

fn verify_p256(
    key: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if key.algorithm.oid.to_string() != EC_KEY {
        return Err("The public key is not an EC key.".into());
    }
    let point = bit_bytes(&key.subject_public_key);
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| "The public key is not a P-256 point.".to_string())?;
    let parsed = if signature.len() == 64 {
        p256::ecdsa::Signature::from_slice(signature)
    } else {
        p256::ecdsa::Signature::from_der(signature)
    }
    .map_err(|_| "The ECDSA signature could not be parsed.".to_string())?;
    p256::ecdsa::signature::Verifier::verify(&verifying, message, &parsed)
        .map_err(|_| "The ECDSA signature is not valid.".to_string())
}

fn verify_rsa(
    key: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    algorithm: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if key.algorithm.oid.to_string() != RSA_KEY {
        return Err("The public key is not an RSA key.".into());
    }
    let public = rsa::RsaPublicKey::from_pkcs1_der(bit_bytes(&key.subject_public_key))
        .map_err(|_| "The RSA public key could not be parsed.".to_string())?;
    let parsed = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| "The RSA signature could not be parsed.".to_string())?;
    match algorithm {
        RSA_SHA256 => rsa::signature::Verifier::verify(
            &rsa::pkcs1v15::VerifyingKey::<sha2_legacy::Sha256>::new(public),
            message,
            &parsed,
        ),
        RSA_SHA384 => rsa::signature::Verifier::verify(
            &rsa::pkcs1v15::VerifyingKey::<sha2_legacy::Sha384>::new(public),
            message,
            &parsed,
        ),
        RSA_SHA512 => rsa::signature::Verifier::verify(
            &rsa::pkcs1v15::VerifyingKey::<sha2_legacy::Sha512>::new(public),
            message,
            &parsed,
        ),
        other => return Err(format!("Unsupported RSA signature algorithm {other}.")),
    }
    .map_err(|_| "The RSA signature is not valid.".to_string())
}

struct Details {
    subject: String,
    device: Option<String>,
    firmware: Option<String>,
    serial: Option<String>,
}

fn cert_details(cert: &Certificate) -> Details {
    Details {
        subject: cert.tbs_certificate.subject.to_string(),
        device: extension(cert, DEVICE_TYPE).and_then(der_string),
        firmware: extension(cert, FIRMWARE).and_then(firmware_string),
        serial: extension(cert, SERIAL)
            .and_then(der_uint)
            .map(|value| value.to_string()),
    }
}

fn extension<'a>(cert: &'a Certificate, oid: &str) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id.to_string() == oid)
                .map(|extension| extension.extn_value.as_bytes())
        })
}

fn firmware_string(bytes: &[u8]) -> Option<String> {
    let raw = der_octets(bytes).unwrap_or(bytes);
    if raw.len() < 3 {
        return None;
    }
    Some(format!("{}.{}.{}", raw[0], raw[1], raw[2]))
}

fn der_string(bytes: &[u8]) -> Option<String> {
    let (tag, value) = der_body(bytes)?;
    if !matches!(tag, 0x0c | 0x13 | 0x16) {
        return None;
    }
    String::from_utf8(value.to_vec()).ok()
}

fn der_octets(bytes: &[u8]) -> Option<&[u8]> {
    let (tag, value) = der_body(bytes)?;
    if tag == 0x04 { Some(value) } else { None }
}

fn der_uint(bytes: &[u8]) -> Option<u64> {
    let (tag, value) = der_body(bytes)?;
    if tag != 0x02 || value.is_empty() || value.len() > 8 {
        return None;
    }
    Some(
        value
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
    )
}

fn der_body(bytes: &[u8]) -> Option<(u8, &[u8])> {
    if bytes.len() < 2 {
        return None;
    }
    let (len, rest) = der_length(&bytes[1..])?;
    if rest.len() < len {
        return None;
    }
    Some((bytes[0], &rest[..len]))
}

fn der_length(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((first as usize, &bytes[1..]));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || bytes.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for byte in &bytes[1..=count] {
        len = (len << 8) | usize::from(*byte);
    }
    Some((len, &bytes[1 + count..]))
}

fn bundle() -> &'static [Certificate] {
    static BUNDLE: OnceLock<Vec<Certificate>> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let mut certs = parse_pems(ROOTS_PEM);
        certs.extend(parse_pems(INTERMEDIATES_PEM));
        certs
    })
}

fn parse_pems(text: &str) -> Vec<Certificate> {
    let mut certs = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let Some(end) = after.find(END) else { break };
        let pem = &after[..end + END.len()];
        certs.push(Certificate::from_pem(pem).expect("embedded Yubico certificate"));
        rest = &after[end + END.len()..];
    }
    certs
}

fn name_bytes(name: &x509_cert::name::Name) -> Result<Vec<u8>, der::Error> {
    name.to_der()
}

fn bit_bytes(bits: &der::asn1::BitString) -> &[u8] {
    bits.as_bytes().unwrap_or_else(|| bits.raw_bytes())
}

fn field<'a>(
    entries: &'a [(cbor::Value, cbor::Value)],
    key: &cbor::Value,
) -> Option<&'a cbor::Value> {
    entries
        .iter()
        .find(|(entry, _)| entry == key)
        .map(|(_, value)| value)
}

fn text_field(entries: &[(cbor::Value, cbor::Value)], name: &str) -> Result<String, String> {
    match field(entries, &cbor::Value::Text(name.into())) {
        Some(cbor::Value::Text(value)) => Ok(value.clone()),
        _ => Err(format!("The attestation has no {name}.")),
    }
}

fn bytes_field<'a>(
    entries: &'a [(cbor::Value, cbor::Value)],
    name: &str,
) -> Result<&'a [u8], String> {
    match field(entries, &cbor::Value::Text(name.into())) {
        Some(cbor::Value::Bytes(value)) => Ok(value),
        _ => Err(format!("The attestation has no {name}.")),
    }
}

fn map_field<'a>(
    entries: &'a [(cbor::Value, cbor::Value)],
    name: &str,
) -> Result<&'a [(cbor::Value, cbor::Value)], String> {
    match field(entries, &cbor::Value::Text(name.into())) {
        Some(cbor::Value::Map(value)) => Ok(value),
        _ => Err(format!("The attestation has no {name}.")),
    }
}

fn bytes_at(entries: &[(cbor::Value, cbor::Value)], key: i64) -> Result<&[u8], String> {
    match field(entries, &cbor::Value::Int(key)) {
        Some(cbor::Value::Bytes(value)) => Ok(value),
        _ => Err("The COSE key is missing a coordinate.".into()),
    }
}

fn decode_b64(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| "Attestation data is not valid base64.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_certificate_chains_to_a_yubico_root() {
        let certs = bundle();
        assert!(certs.len() >= 5, "expected the published Yubico CAs");
        for cert in certs {
            assert!(
                chains_to_yubico(cert, &[]),
                "{} does not chain to a bundled root",
                cert.tbs_certificate.subject
            );
        }
    }
}
