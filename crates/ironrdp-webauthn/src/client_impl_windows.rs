use ironrdp_pdu::PduResult;
use tracing::{error, info};

use crate::pdu::{RpcCommand, WebAuthnChannelRequest, WebAuthnResponse, WebAuthnResponseData};

#[link(name = "webauthn")]
extern "system" {
    fn WebAuthNGetApiVersionNumber() -> u32;
}

const WEBAUTHN_API_VERSION_4: u32 = 4;

pub fn handle_webauthn_request(req: WebAuthnChannelRequest) -> PduResult<WebAuthnResponse> {
    match req.rpc_command() {
        RpcCommand::ApiVersion => {
            let version = unsafe { WebAuthNGetApiVersionNumber() };
            info!("Windows WebAuthn API Version: {}", version);
            Ok(WebAuthnResponse {
                hresult: 0,
                data: WebAuthnResponseData::ApiVersion(version),
            })
        }
        RpcCommand::WebAuthn => {
            // TODO: Implement full mapping from CTAP to Windows WebAuthn API
            // This requires decoding the CBOR in req.request, mapping to WEBAUTHN_* structs,
            // calling WebAuthNAuthenticatorMakeCredential/GetAssertion, and mapping back.
            error!("WebAuthn operation not yet fully implemented on Windows");
            Ok(WebAuthnResponse {
                hresult: 0x80004001, // E_NOTIMPL
                data: WebAuthnResponseData::CancelCurrentOp,
            })
        }
        RpcCommand::Iuvpaa => {
            // Check if platform authenticator is available
            let version = unsafe { WebAuthNGetApiVersionNumber() };
            let available = version >= WEBAUTHN_API_VERSION_4;
            Ok(WebAuthnResponse {
                hresult: 0,
                data: WebAuthnResponseData::Iuvpaa(available),
            })
        }
        RpcCommand::CancelCurrentOp => {
            // Cancellation is handled by GUID. We need to track active operations.
            // For now, since we don't have long running ops implemented, just ACK.
            Ok(WebAuthnResponse {
                hresult: 0,
                data: WebAuthnResponseData::CancelCurrentOp,
            })
        }
        _ => {
            error!("Unknown RPC command");
            Ok(WebAuthnResponse {
                hresult: 0x80004001,
                data: WebAuthnResponseData::CancelCurrentOp,
            })
        }
    }
}
