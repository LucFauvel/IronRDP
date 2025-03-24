use ironrdp_core::impl_as_any;
use ironrdp_dvc::{DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_pdu::PduResult;
use crate::CHANNEL_NAME;

/// A client for the Display Control Virtual Channel.
pub struct WebAuthnClient {
}

impl WebAuthnClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl_as_any!(WebAuthnClient);

impl DvcProcessor for WebAuthnClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        Ok(Vec::new())
    }
}

impl DvcClientProcessor for WebAuthnClient {}
