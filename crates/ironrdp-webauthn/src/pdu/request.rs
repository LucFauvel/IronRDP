use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthNParams {
    #[serde(rename = "wnd")]
    pub window_handle: u32, // "wnd": window handle for the caller

    #[serde(rename = "attachment")]
    pub attachment: Option<u32>, // map to AuthenticatorAttachment

    #[serde(rename = "requireResident")]
    pub require_resident: Option<bool>,

    #[serde(rename = "preferResident")]
    pub prefer_resident: Option<bool>,

    #[serde(rename = "userVerification")]
    pub user_verification: Option<u32>, // map to UserVerificationRequirement

    #[serde(rename = "attestationPreference")]
    pub attestation_preference: Option<u32>, // AttestationConveyancePreference

    #[serde(rename = "enterpriseAttestation")]
    pub enterprise_attestation: Option<u32>, // EnterpriseAttestation

    #[serde(rename = "cancellationId", with = "serde_bytes", default)]
    pub cancellation_id: Vec<u8>, // GUID (16 bytes)
}

impl WebAuthNParams {
    pub fn attachment_enum(&self) -> Option<AuthenticatorAttachment> {
        self.attachment.and_then(AuthenticatorAttachment::from_u32)
    }

    pub fn user_verification_enum(&self) -> Option<UserVerificationRequirement> {
        self.user_verification.and_then(UserVerificationRequirement::from_u32)
    }

    pub fn attestation_preference_enum(&self) -> Option<AttestationConveyancePreference> {
        self.attestation_preference
            .and_then(AttestationConveyancePreference::from_u32)
    }

    pub fn enterprise_attestation_enum(&self) -> Option<EnterpriseAttestation> {
        self.enterprise_attestation
            .and_then(EnterpriseAttestation::from_u32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnChannelRequest {
    // "command": RPC command type (5..8)
    #[serde(rename = "command")]
    pub command: u32, // convert to RpcCommand via helper

    // "request": bytes content varies by command.
    //
    // - For CTAPCBOR_RPC_COMMAND_IUVPAA: not present.
    // - For CTAPCBOR_RPC_COMMAND_CANCEL_CUR_OP: GUID representing current operation.
    // - For CTAPCBOR_RPC_COMMAND_WEB_AUTHN:
    //     first byte: WebAuthnCtapCommand (0x01/0x02),
    //     remaining bytes: CBOR map defined in FIDO-CTAP.
    #[serde(rename = "request", with = "serde_bytes", default)]
    pub request: Vec<u8>,

    // "flags": bitfield of CTAPCLT_* flags
    #[serde(rename = "flags")]
    pub flags: u32, // map to CtapClientFlags

    // "timeout" in milliseconds
    #[serde(rename = "timeout")]
    pub timeout_ms: u32,

    // "transactionId": GUID for the transaction
    #[serde(rename = "transactionId", with = "serde_bytes")]
    pub transaction_id: Vec<u8>, // expect 16 bytes

    // "webAuthNPara": optional parameter map
    #[serde(rename = "webAuthNPara")]
    pub web_authn_params: Option<WebAuthNParams>,
}

impl WebAuthnChannelRequest {
    pub fn rpc_command(&self) -> RpcCommand {
        RpcCommand::from(self.command)
    }

    pub fn ctap_webauthn_command(&self) -> Option<WebAuthnCtapCommand> {
        if self.rpc_command() != RpcCommand::WebAuthn {
            return None;
        }
        let cmd = *self.request.first()?;
        Some(WebAuthnCtapCommand::from(cmd))
    }

    pub fn ctap_payload(&self) -> Option<&[u8]> {
        if self.rpc_command() != RpcCommand::WebAuthn {
            return None;
        }
        Some(self.request.get(1..).unwrap_or(&[]))
    }

    pub fn cancellation_guid(&self) -> Option<&[u8]> {
        (self.rpc_command() == RpcCommand::CancelCurrentOp).then_some(self.request.as_slice())
    }

    pub fn flags(&self) -> Option<CtapClientFlags> {
        CtapClientFlags::from_bits(self.flags)
    }
}
