use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnResponseMessage {
    pub hresult: u32,
    pub response: Vec<u8>,
    pub device_info: DeviceInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub max_msg_size: u32,
    pub max_serialized_large_blob_array: u32,
    pub provider_type: CtapProviderType,
    pub provider_name: String,
    pub device_path: String,
    #[serde(alias = "Manufacturer")]
    pub manufacturer: String,
    #[serde(alias = "Product")]
    pub product: String,
    pub aa_guid: Vec<u8>,
    pub resident_key: bool,
    pub uv_status: u32,
    pub uv_retries: u32,
}

pub enum CtapProviderType {
    Hid,
    Nfc,
    Ble,
    Platform
}