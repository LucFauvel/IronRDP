use alloc::string::String;
use alloc::vec::Vec;

use ironrdp_core::{Encode, EncodeResult, WriteCursor};
use ironrdp_dvc::DvcEncode;
use serde::{Deserialize, Serialize};

use super::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    #[serde(rename = "maxMsgSize")]
    pub max_msg_size: Option<u32>,

    #[serde(rename = "maxSerializedLargeBlobArray")]
    pub max_serialized_large_blob_array: Option<u32>,

    #[serde(rename = "providerType")]
    pub provider_type: Option<String>, // "Hid", "Nfc", "Ble", "Platform"

    #[serde(rename = "providerName")]
    pub provider_name: Option<String>,

    #[serde(rename = "devicePath")]
    pub device_path: Option<String>,

    #[serde(rename = "Manufacturer")]
    pub manufacturer: Option<String>,

    #[serde(rename = "Product")]
    pub product: Option<String>,

    #[serde(rename = "aaGuid", with = "serde_bytes")]
    pub aa_guid: Option<Vec<u8>>, // 16 bytes
}

// 2.2.2.1 CTAPCBOR_RPC_COMMAND_WEB_AUTHN Response Map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnOperationResponseMap {
    #[serde(rename = "deviceInfo")]
    pub device_info: Option<DeviceInfo>,

    #[serde(rename = "residentKey")]
    pub resident_key: Option<bool>,

    #[serde(rename = "uvStatus")]
    pub uv_status: Option<u32>, // map to UserVerificationRequirement

    #[serde(rename = "uvRetries")]
    pub uv_retries: Option<u32>,

    #[serde(rename = "Status")]
    pub status: u32, // overall operation status (spec-defined values)

    // "Response": bstr = status byte + CBOR map (FIDO-CTAP)
    #[serde(rename = "Response", with = "serde_bytes")]
    pub response_raw: Vec<u8>,
}

impl WebAuthnOperationResponseMap {
    pub fn uv_status_enum(&self) -> Option<UserVerificationRequirement> {
        self.uv_status.and_then(UserVerificationRequirement::from_u32)
    }

    // parse the Response field into (ctap_status, ctap_cbor)
    pub fn parse_ctap_response(&self) -> Option<(u8, &[u8])> {
        let (status, rest) = self.response_raw.split_first()?;
        Some((*status, rest))
    }
}

#[derive(Debug, Clone)]
pub enum WebAuthnResponseData {
    WebAuthn(WebAuthnOperationResponseMap),
    Iuvpaa(bool),
    CancelCurrentOp,
    ApiVersion(u32),
}

#[derive(Debug, Clone)]
pub struct WebAuthnResponse {
    pub hresult: u32,
    pub data: WebAuthnResponseData,
}

#[derive(Debug, Clone)]
pub struct WebAuthnResponsePdu {
    pub hresult: u32,
    pub payload: Vec<u8>,
}

impl WebAuthnResponsePdu {
    const NAME: &'static str = "WebAuthN_Channel_Response";
}

impl From<WebAuthnResponse> for WebAuthnResponsePdu {
    fn from(response: WebAuthnResponse) -> Self {
        let payload = match response.data {
            WebAuthnResponseData::WebAuthn(map) => {
                let mut buf = Vec::new();
                // We panic on encoding error because these structures are controlled by us and should be serializable.
                ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encode failed");
                buf
            }
            WebAuthnResponseData::Iuvpaa(b) => {
                let value: u32 = if b { 1 } else { 0 };
                value.to_le_bytes().to_vec()
            }
            WebAuthnResponseData::CancelCurrentOp => Vec::new(),
            WebAuthnResponseData::ApiVersion(v) => v.to_le_bytes().to_vec(),
        };

        Self {
            hresult: response.hresult,
            payload,
        }
    }
}

impl Encode for WebAuthnResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32(self.hresult);
        dst.write_slice(&self.payload);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        4 + self.payload.len()
    }
}

impl DvcEncode for WebAuthnResponsePdu {}
