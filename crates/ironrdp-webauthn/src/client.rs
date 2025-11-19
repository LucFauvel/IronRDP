use alloc::boxed::Box;
use alloc::vec::Vec;

use ironrdp_core::impl_as_any;
use ironrdp_dvc::{DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_pdu::PduResult;
use tracing::debug;

use crate::pdu::{WebAuthnChannelRequest, WebAuthnResponse, WebAuthnResponsePdu};
use crate::CHANNEL_NAME;

type OnRequest = Box<dyn Fn(WebAuthnChannelRequest) -> PduResult<WebAuthnResponse> + Send>;

pub struct WebAuthnClient {
    on_request: OnRequest,
}

impl WebAuthnClient {
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(WebAuthnChannelRequest) -> PduResult<WebAuthnResponse> + Send + 'static,
    {
        Self {
            on_request: Box::new(callback),
        }
    }

    #[cfg(all(feature = "std", windows))]
    pub fn new_default() -> Self {
        Self::new(crate::client_impl_windows::handle_webauthn_request)
    }

    #[cfg(all(feature = "std", target_family = "wasm"))]
    pub fn new_default() -> Self {
        Self::new(crate::client_impl_wasm::handle_webauthn_request)
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
        // ciborium::de::from_reader requires std::io::Read, which &[u8] implements in std.
        // Since this crate currently targets std (based on ironrdp-displaycontrol precedent), this works.
        let req: WebAuthnChannelRequest = ciborium::de::from_reader(payload).map_err(|_e| {
            ironrdp_pdu::PduError::new(
                "WebAuthnClient",
                ironrdp_pdu::PduErrorKind::Other {
                    description: "CBOR decode failed",
                },
            )
        })?;

        debug!(?req, "Received WebAuthN_Channel request");

        let resp = (self.on_request)(req)?;

        let pdu = WebAuthnResponsePdu::from(resp);

        debug!(?pdu, "Sending WebAuthN_Channel response");

        Ok(vec![Box::new(pdu)])
    }
}

impl DvcClientProcessor for WebAuthnClient {}
