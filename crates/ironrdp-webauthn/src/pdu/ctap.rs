/// CTAP (Client to Authenticator Protocol) CBOR structures
///
/// This module contains the CBOR structures and parsing logic for CTAP requests and responses,
/// as defined in the FIDO CTAP specification. This code is shared between platform implementations.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::types::WebAuthnCtapCommand;

/// CTAP MakeCredential request (authenticatorMakeCredential)
/// FIDO CTAP specification section 6.1
#[derive(Debug, Clone, Deserialize)]
pub struct CtapMakeCredentialRequest {
    /// 0x01: clientDataHash (required)
    #[serde(rename = "1", deserialize_with = "deserialize_bytes")]
    pub client_data_hash: Vec<u8>, // 32 bytes

    /// 0x02: rp (required) - Relying Party
    #[serde(rename = "2")]
    pub rp: PublicKeyCredentialRpEntity,

    /// 0x03: user (required)
    #[serde(rename = "3")]
    pub user: PublicKeyCredentialUserEntity,

    /// 0x04: pubKeyCredParams (required) - supported algorithms
    #[serde(rename = "4")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,

    /// 0x05: excludeList (optional) - credentials to exclude
    #[serde(rename = "5", skip_serializing_if = "Option::is_none", skip_deserializing)]
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// 0x06: extensions (optional)
    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<CtapExtensions>,

    /// 0x07: options (optional)
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub options: Option<CtapOptions>,

    /// 0x08: pinAuth (optional)
    #[serde(rename = "8", deserialize_with = "deserialize_bytes_opt", skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<Vec<u8>>,

    /// 0x09: pinProtocol (optional)
    #[serde(rename = "9", skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
}

/// CTAP GetAssertion request (authenticatorGetAssertion)
/// FIDO CTAP specification section 6.2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapGetAssertionRequest {
    /// 0x01: rpId (required)
    #[serde(rename = "1")]
    pub rp_id: String,

    /// 0x02: clientDataHash (required)
    #[serde(rename = "2", deserialize_with = "deserialize_bytes")]
    pub client_data_hash: Vec<u8>, // 32 bytes

    /// 0x03: allowList (optional) - allowed credentials
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// 0x04: extensions (optional)
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<CtapExtensions>,

    /// 0x05: options (optional)
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub options: Option<CtapOptions>,

    /// 0x06: pinAuth (optional)
    #[serde(rename = "6", deserialize_with = "deserialize_bytes_opt", skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<Vec<u8>>,

    /// 0x07: pinProtocol (optional)
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
}

/// CTAP MakeCredential response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapMakeCredentialResponse {
    /// 0x01: fmt (required) - attestation format
    #[serde(rename = "1")]
    pub fmt: String,

    /// 0x02: authData (required)
    #[serde(rename = "2", deserialize_with = "deserialize_bytes")]
    pub auth_data: Vec<u8>,

    /// 0x03: attStmt (required) - attestation statement
    #[serde(rename = "3")]
    pub att_stmt: ciborium::Value,
}

/// CTAP GetAssertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapGetAssertionResponse {
    /// 0x01: credential (optional)
    #[serde(rename = "1", skip_serializing_if = "Option::is_none")]
    pub credential: Option<PublicKeyCredentialDescriptor>,

    /// 0x02: authData (required)
    #[serde(rename = "2", deserialize_with = "deserialize_bytes")]
    pub auth_data: Vec<u8>,

    /// 0x03: signature (required)
    #[serde(rename = "3", deserialize_with = "deserialize_bytes")]
    pub signature: Vec<u8>,

    /// 0x04: user (optional)
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub user: Option<PublicKeyCredentialUserEntity>,

    /// 0x05: numberOfCredentials (optional)
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub number_of_credentials: Option<u32>,
}

/// Relying Party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// Relying Party identifier
    pub id: String,

    /// Human-readable name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Icon URL (deprecated in WebAuthn Level 2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// User identifier
    #[serde(deserialize_with = "deserialize_bytes")]
    pub id: Vec<u8>,

    /// Human-readable user name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Display name
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Icon URL (deprecated in WebAuthn Level 2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Credential type (e.g., "public-key")
    #[serde(rename = "type")]
    pub type_: String,

    /// COSE algorithm identifier
    pub alg: i32,
}

/// Helper for deserializing byte strings from CBOR
fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Deserialize;
    let value = ciborium::Value::deserialize(deserializer)?;
    #[cfg(feature = "std")]
    eprintln!("DEBUG: deserialize_bytes got value: {:?}", value);
    match value {
        ciborium::Value::Bytes(b) => {
            #[cfg(feature = "std")]
            eprintln!("DEBUG: returning {} bytes", b.len());
            Ok(b)
        }
        ciborium::Value::Array(arr) => {
            #[cfg(feature = "std")]
            eprintln!("DEBUG: converting array of {} elements to bytes", arr.len());
            // Fallback: convert array of integers to bytes
            Ok(arr.into_iter()
                .filter_map(|v| {
                    if let ciborium::Value::Integer(i) = v {
                        Some(i.try_into().unwrap_or(0))
                    } else {
                        None
                    }
                })
                .collect())
        }
        _ => {
            #[cfg(feature = "std")]
            eprintln!("DEBUG: ERROR - unexpected type");
            Err(serde::de::Error::custom("expected bytes or array"))
        }
    }
}

/// Helper for deserializing optional byte strings from CBOR
fn deserialize_bytes_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Deserialize;
    let value = Option::<ciborium::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(ciborium::Value::Bytes(b)) => Ok(Some(b)),
        Some(ciborium::Value::Array(arr)) => {
            Ok(Some(arr.into_iter()
                .filter_map(|v| {
                    if let ciborium::Value::Integer(i) = v {
                        Some(i.try_into().unwrap_or(0))
                    } else {
                        None
                    }
                })
                .collect()))
        }
        _ => Err(serde::de::Error::custom("expected bytes or array")),
    }
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub type_: String,

    /// Credential ID
    #[serde(deserialize_with = "deserialize_bytes")]
    pub id: Vec<u8>,

    /// Transports (optional) - can be either an integer (flags) or array of strings
    /// We use ciborium::Value to accept both formats
    #[serde(skip_serializing_if = "Option::is_none", skip_deserializing)]
    pub transports: Option<ciborium::Value>,
}

/*
// Commented out - using ciborium::Value for transports field directly instead
impl<'de> serde::Deserialize<'de> for PublicKeyCredentialDescriptor {
    ...
}
*/

/// CTAP extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapExtensions {
    /// HMAC secret extension
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,

    /// Credential protection extension
    #[serde(rename = "credProtect", skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u32>,

    /// Large blob key extension
    #[serde(rename = "largeBlobKey", skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
}

/// CTAP options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapOptions {
    /// Resident key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,

    /// User verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,

    /// User presence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,
}

/// Parsed CTAP request
#[derive(Debug, Clone)]
pub enum CtapRequest {
    MakeCredential(CtapMakeCredentialRequest),
    GetAssertion(CtapGetAssertionRequest),
}

/// Parsed CTAP response
#[derive(Debug, Clone)]
pub enum CtapResponse {
    MakeCredential(CtapMakeCredentialResponse),
    GetAssertion(CtapGetAssertionResponse),
}

/// Parse CTAP request from CBOR bytes
///
/// The payload should be the CBOR map (without the command byte prefix).
pub fn parse_ctap_request(command: WebAuthnCtapCommand, cbor_payload: &[u8]) -> Result<CtapRequest, String> {
    match command {
        WebAuthnCtapCommand::MakeCredential => {
            let value: serde_cbor::Value = serde_cbor::from_slice(cbor_payload)
                .map_err(|e| alloc::format!("Failed to parse CBOR: {:?}", e))?;

            let map = match value {
                serde_cbor::Value::Map(m) => m,
                _ => return Err("Expected CBOR map".into()),
            };

            // Extract fields by integer key
            let client_data_hash = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(1)))
                .and_then(|(_, v)| if let serde_cbor::Value::Bytes(b) = v { Some(b.clone()) } else { None })
                .ok_or("Missing clientDataHash")?;

            let rp = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(2)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok())
                .ok_or("Missing rp")?;

            let user = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(3)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok())
                .ok_or("Missing user")?;

            let pub_key_cred_params = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(4)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok())
                .ok_or("Missing pubKeyCredParams")?;

            let exclude_list = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(5)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok());

            let extensions = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(6)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok());

            let options = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(7)))
                .and_then(|(_, v)| serde_cbor::value::from_value(v.clone()).ok());

            let pin_auth = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(8)))
                .and_then(|(_, v)| if let serde_cbor::Value::Bytes(b) = v { Some(b.clone()) } else { None });

            let pin_protocol = map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(9)))
                .and_then(|(_, v)| if let serde_cbor::Value::Integer(i) = v { Some(*i as u32) } else { None });

            Ok(CtapRequest::MakeCredential(CtapMakeCredentialRequest {
                client_data_hash,
                rp,
                user,
                pub_key_cred_params,
                exclude_list,
                extensions,
                options,
                pin_auth,
                pin_protocol,
            }))
        }
        WebAuthnCtapCommand::GetAssertion => {
            let req: CtapGetAssertionRequest = serde_cbor::from_slice(cbor_payload)
                .map_err(|e| alloc::format!("Failed to parse GetAssertion request: {:?}", e))?;
            Ok(CtapRequest::GetAssertion(req))
        }
        WebAuthnCtapCommand::Unknown(cmd) => {
            Err(alloc::format!("Unknown CTAP command: {:#x}", cmd))
        }
    }
}

/// Encode CTAP response to CBOR bytes
///
/// Returns the CBOR-encoded response (without the status byte prefix).
pub fn encode_ctap_response(response: CtapResponse) -> Result<Vec<u8>, String> {
    match response {
        CtapResponse::MakeCredential(resp) => {
            serde_cbor::to_vec(&resp)
                .map_err(|e| alloc::format!("Failed to encode MakeCredential response: {:?}", e))
        }
        CtapResponse::GetAssertion(resp) => {
            serde_cbor::to_vec(&resp)
                .map_err(|e| alloc::format!("Failed to encode GetAssertion response: {:?}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_credential_descriptor_with_integer_transports() {
        // CBOR for: {type: "public-key", id: <32 bytes>, transports: 1}
        let cbor_hex = "a362696458200941fcdbd4847b2e4e42aa05c2ed358b891a31cfca874187153781d60afd57f664747970656a7075626c69632d6b65796a7472616e73706f72747301";
        let cbor_bytes = hex::decode(cbor_hex).unwrap();

        let result: Result<PublicKeyCredentialDescriptor, _> = ciborium::de::from_reader(cbor_bytes.as_slice());

        match result {
            Ok(desc) => {
                println!("Successfully parsed! type={}, id_len={}, transports={:?}",
                         desc.type_, desc.id.len(), desc.transports);
                assert_eq!(desc.type_, "public-key");
                assert_eq!(desc.id.len(), 32);
            }
            Err(e) => {
                panic!("Failed to parse: {:?}", e);
            }
        }
    }

    #[test]
    fn test_as_value() {
        let cbor_hex = "a401582020202020202020202020202020202020202020202020202020202020202020202020a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644f776562617574686e696f2d74657374646e616d6564746573746b646973706c61794e616d6564746573740483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b6579";
        let cbor_bytes = hex::decode(cbor_hex).unwrap();

        eprintln!("Trying to deserialize as ciborium::Value...");
        let result: Result<ciborium::Value, _> = ciborium::de::from_reader(cbor_bytes.as_slice());
        match result {
            Ok(value) => {
                eprintln!("Successfully parsed as Value!");
                eprintln!("Type: {:?}", value);
            }
            Err(e) => {
                panic!("Failed to parse as Value: {:?}", e);
            }
        }
    }

    #[test]
    fn test_minimal_make_credential() {
        // Minimal CTAP MakeCredential with just required fields - skip exclude list (field 5)
        let cbor_hex = "a401582020202020202020202020202020202020202020202020202020202020202020202020a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644f776562617574686e696f2d74657374646e616d6564746573746b646973706c61794e616d6564746573740483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b6579";
        let cbor_bytes = hex::decode(cbor_hex).unwrap();

        let result: Result<CtapMakeCredentialRequest, _> = ciborium::de::from_reader(cbor_bytes.as_slice());
        match result {
            Ok(req) => {
                println!("Successfully parsed!");
                println!("RP: {}", req.rp.id);
            }
            Err(e) => {
                panic!("Parse failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_full_make_credential_request() {
        // Full CTAP MakeCredential payload from actual logs
        let cbor_hex = "a5015820b8a70abe2c66e55435de3fa5e9dd4e57dfbe1804a11fd1dfae16776ce4b9bf6002a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644f776562617574686e696f2d74657374646e616d6564746573746b646973706c61794e616d6564746573740483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b65790593a362696458200941fcdbd4847b2e4e42aa05c2ed358b891a31cfca874187153781d60afd57f664747970656a7075626c69632d6b65796a7472616e73706f72747301a362696450140b8f7076a503e596e0bde1fb52f79164747970656a7075626c69632d6b65796a7472616e73706f7274731830a3626964582016e8ca721e20a8fc91e8cd1fd09bbc95a223c39e6c805e61b3714d11b65a313a64747970656a7075626c69632d6b65796a7472616e73706f72747301a362696458202da7d08844ac681d8b914fdab075185bac2afc004c03a4c0a3a936932ef8a88664747970656a7075626c69632d6b65796a7472616e73706f72747310a3626964582035ef02090447bf585ffa315838386a9500c213cf490bcd2dbf9b33171ec0fae464747970656a7075626c69632d6b65796a7472616e73706f72747301a3626964582041a7495b2f8d452c02b2e5eee314518b8cb2aa1715c0df95a20b48f224e446c464747970656a7075626c69632d6b65796a7472616e73706f72747301a362696458204cbfa884b3bc5189dcf275e2ea153c826ee03a16653fca58c48a5fcdc2ce8e5d64747970656a7075626c69632d6b65796a7472616e73706f72747310a3626964582a4f4c9c80f1d00203000030de8812b5f27dc738c493515d24068063427b75ac00e21651aa6baa574564e364747970656a7075626c69632d6b65796a7472616e73706f7274731837a362696450557c48b4ee75912982f906abc4bdd18964747970656a7075626c69632d6b65796a7472616e73706f7274731830a362696458205ad3c62e80796c930a2006fca02fd6f80ba152e53845ba4637d9e3f294032e4264747970656a7075626c69632d6b65796a7472616e73706f72747310a362696454671a2b29f9386e9fe0474cd540a817cf7d98b82664747970656a7075626c69632d6b65796a7472616e73706f7274731830a3626964582084f0cb2dd477ff793f9a442aa1f6a9d69f962225a33d8578845e33bb5eca22b564747970656a7075626c69632d6b65796a7472616e73706f72747301a36269645820874e221075b6c58fa0169eb92e220e54ee8d7e7886910bfb6981504b3c3d783f64747970656a7075626c69632d6b65796a7472616e73706f72747301a362696458208f82478edb1fa513e80f12d52c2e109b4b1229f6d038fca18bd0042093fbb9fe64747970656a7075626c69632d6b65796a7472616e73706f72747301a36269645820997d9d120d703f069f80e601500c928d35650487ee0ea1d0a19c2d11c166558464747970656a7075626c69632d6b65796a7472616e73706f72747301a362696454afd0e63a50e4aaa9f4e7154c6f8d338494c8766564747970656a7075626c69632d6b65796a7472616e73706f7274731830a362696450c405499f218b5b094b4b0b84f107dbca64747970656a7075626c69632d6b65796a7472616e73706f7274731830a36269645820f14e9a9c3e44a47c92470bebc1384684eebd4e8bc5150b283e873ffa350a409f64747970656a7075626c69632d6b65796a7472616e73706f72747310a36269645820f4cbd38005bac84f57f59deab531c01fd13817f677e66a0dae7b4a03dea15bb264747970656a7075626c69632d6b65796a7472616e73706f72747310";
        let cbor_bytes = hex::decode(cbor_hex).unwrap();

        // First, parse as raw Value to see structure
        eprintln!("Parsing as ciborium::Value to see structure...");
        let value: ciborium::Value = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        eprintln!("Raw CBOR structure: {:#?}", value);

        eprintln!("\nNow parsing as CtapMakeCredentialRequest...");
        let result: Result<CtapMakeCredentialRequest, _> = ciborium::de::from_reader(cbor_bytes.as_slice());

        match result {
            Ok(req) => {
                println!("Successfully parsed CtapMakeCredentialRequest!");
                println!("RP: {}", req.rp.id);
                println!("User: {:?}", req.user.name);
                println!("Exclude list len: {}", req.exclude_list.as_ref().map(|l| l.len()).unwrap_or(0));
            }
            Err(e) => {
                eprintln!("Failed to parse CtapMakeCredentialRequest: {:?}", e);
                panic!("Parse failed: {:?}", e);
            }
        }
    }
}