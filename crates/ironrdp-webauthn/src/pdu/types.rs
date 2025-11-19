use bitflags::bitflags;

// 2.2.1 WebAuthN_Channel Request Message - RPC command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcCommand {
    WebAuthn,          // CTAPCBOR_RPC_COMMAND_WEB_AUTHN = 5
    Iuvpaa,            // CTAPCBOR_RPC_COMMAND_IUVPAA = 6
    CancelCurrentOp,   // CTAPCBOR_RPC_COMMAND_CANCEL_CUR_OP = 7
    ApiVersion,        // CTAPCBOR_RPC_COMMAND_API_VERSION = 8
    Unknown(u32),
}

impl From<u32> for RpcCommand {
    fn from(value: u32) -> Self {
        match value {
            5 => Self::WebAuthn,
            6 => Self::Iuvpaa,
            7 => Self::CancelCurrentOp,
            8 => Self::ApiVersion,
            n => Self::Unknown(n),
        }
    }
}

impl From<RpcCommand> for u32 {
    fn from(val: RpcCommand) -> Self {
        match val {
            RpcCommand::WebAuthn => 5,
            RpcCommand::Iuvpaa => 6,
            RpcCommand::CancelCurrentOp => 7,
            RpcCommand::ApiVersion => 8,
            RpcCommand::Unknown(n) => n,
        }
    }
}

// 2.2.1 – WebAuthn command byte inside "request" for CTAPCBOR_RPC_COMMAND_WEB_AUTHN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnCtapCommand {
    MakeCredential, // CTAPCBOR_CMD_MAKE_CREDENTIAL = 0x01
    GetAssertion,   // CTAPCBOR_CMD_GET_ASSERTION = 0x02
    Unknown(u8),
}

impl From<u8> for WebAuthnCtapCommand {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::MakeCredential,
            0x02 => Self::GetAssertion,
            n => Self::Unknown(n),
        }
    }
}

impl From<WebAuthnCtapCommand> for u8 {
    fn from(val: WebAuthnCtapCommand) -> Self {
        match val {
            WebAuthnCtapCommand::MakeCredential => 0x01,
            WebAuthnCtapCommand::GetAssertion => 0x02,
            WebAuthnCtapCommand::Unknown(n) => n,
        }
    }
}

// 2.2.1.1 webAuthNPara.attachment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorAttachment {
    Any = 0,           // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY
    Platform = 1,      // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM
    CrossPlatform = 2, // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
}

impl AuthenticatorAttachment {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Any),
            1 => Some(Self::Platform),
            2 => Some(Self::CrossPlatform),
            _ => None,
        }
    }
}

// 2.2.1.1 webAuthNPara.userVerification / 2.2.2.1 uvStatus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerificationRequirement {
    Any = 0,         // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY
    Required = 1,    // ..._REQUIRED
    Preferred = 2,   // ..._PREFERRED
    Discouraged = 3, // ..._DISCOURAGED
}

impl UserVerificationRequirement {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Any),
            1 => Some(Self::Required),
            2 => Some(Self::Preferred),
            3 => Some(Self::Discouraged),
            _ => None,
        }
    }
}

// 2.2.1.1 webAuthNPara.attestationPreference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationConveyancePreference {
    Any = 0,      // WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY
    None = 1,     // ..._NONE
    Indirect = 2, // ..._INDIRECT
    Direct = 3,   // ..._DIRECT
}

impl AttestationConveyancePreference {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Any),
            1 => Some(Self::None),
            2 => Some(Self::Indirect),
            3 => Some(Self::Direct),
            _ => None,
        }
    }
}

// 2.2.1.1 webAuthNPara.enterpriseAttestation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterpriseAttestation {
    None = 0,              // WEBAUTHN_ENTERPRISE_ATTESTATION_NONE
    VendorFacilitated = 1, // ..._VENDOR_FACILITATED
    PlatformManaged = 2,   // ..._PLATFORM_MANAGED
}

impl EnterpriseAttestation {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::VendorFacilitated),
            2 => Some(Self::PlatformManaged),
            _ => None,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CtapClientFlags: u32 {
        const U2F              = 0x0002_0000; // CTAPCLT_U2F_FLAG
        const DUAL             = 0x0004_0000; // CTAPCLT_DUAL_FLAG
        const CLIENT_PIN_REQ   = 0x0010_0000; // CTAPCLT_CLIENT_PIN_REQUIRED_FLAG
        const SELECT_CRED_ALLOW_UV = 0x0000_8000; // CTAPCLT_SELECT_CREDENTIAL_ALLOW_UV_FLAG
        const UV_REQUIRED      = 0x0040_0000; // CTAPCLT_UV_REQUIRED_FLAG
        const UV_PREFERRED     = 0x0080_0000; // CTAPCLT_UV_PREFERRED_FLAG
        const UV_NOT_REQUIRED  = 0x0100_0000; // CTAPCLT_UV_NOT_REQUIRED_FLAG
        const HMAC_SECRET      = 0x0400_0000; // CTAPCLT_HMAC_SECRET_EXTENSION_FLAG
        const FORCE_U2F_V2     = 0x0800_0000; // CTAPCLT_FORCE_U2F_V2_FLAG
    }
}
