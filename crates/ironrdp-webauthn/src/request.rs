use bitflags::bitflags;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRequestMessage {
    pub command: WebAuthnCommand,
    pub request: Vec<u8>,
    pub flags: WebauthnRequestFlags,
    pub timeout: u32,
    #[serde(alias="transactionid")]
    pub transaction_id: Vec<u8>,
    pub web_auth_n_para: WebAuthnParameters,
    pub cancellation_id: Vec<u8>
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnParameters {
    pub wnd: u32,
    pub attachment: WebauthnAttachementType,
    pub require_resident: bool,
    pub prefer_resident: bool,
    pub user_verification: WebauthnUserVerificationRequirement,
    pub attestation_preference: WebauthnAttestationPreference,
    pub enterprise_attestation: WebauthnEnterpriseAttestation,
}

#[derive(Deserialize)]
pub enum WebauthnAttestationPreference {
    // Use any attestation conveyance
    // preference.
    WebauthnAttestationConveyancePreferenceAny = 0,
    // No preference among attestation
    // conveyance methods.
    WebauthnAttestationConveyancePreferenceNone = 1,
    // Prefer indirect attestation conveyance.
    WebauthnAttestationConveyancePreferenceIndirect = 2,
    // Prefer direct attestation conveyance.
    WebauthnAttestationConveyancePreferenceDirect = 3,
}

#[derive(Deserialize)]
pub enum WebauthnEnterpriseAttestation {
    // Enterprise attestation is not requested by
    // the relying party.
    WebauthnEnterpriseAttestationNone = 0,
    // Enterprise attestation is requested by the
    // relying party and authenticator can provide
    // it if configured with this relying party.
    WebauthnEnterpriseAttestationVendorFacilitated = 1,
    // Enterprise attestation is requested by the
    // relying party and the platform
    // (OS/browser) if configured with this relying
    // party can allow such attestation.
    WebauthnEnterpriseAttestationPlatformManaged = 2,
}

#[derive(Deserialize)]
pub enum WebauthnUserVerificationRequirement {
    // User verification is not required, and any
    // setting is acceptable to the relying party.
    WebauthnUserVerificationRequirementAny = 0,
    // User verification is required by the relying
    // party.
    WebauthnUserVerificationRequirementRequired = 1,
    // User verification is preferred by the
    // relying party.
    WebauthnUserVerificationRequirementPreferred = 2,
    // User verification is discouraged by the
    // relying party.
    WebauthnUserVerificationRequirementDiscouraged = 3,
}

#[derive(Deserialize)]
pub enum WebauthnAttachementType {
    // Use any authenticator that can satisfy the
    // request conditions.
    WebauthnAuthenticatorAttachmentAny = 0,
    // Use the platform authenticator to satisfy
    // the request conditions.<2>
    WebauthnAuthenticatorAttachmentPlatform = 1,
    // Use the cross-platform roaming
    // authenticator, such as security keys or
    // phones, to satisfy the request conditions.
    WebauthnAuthenticatorAttachmentCrossPlatform = 2,
}

#[derive(Deserialize)]
pub enum WebAuthnCommand {
    // Contains both registration and assertion request for the
    // platform authenticator as well as security keys.
    CtapCborRpcCommandWebAuthn = 5,
    // Corresponds to the WebAuthn
    // IsUserVerifyingPlatformAuthenticatorAvailable API. See
    // [W3C-WebAuthPKC2], section 5.1.7.
    CtapCborRpcCommandIuvpaa = 6,
    // Cancel the current webauthn request.
    CtapCborRpcCommandCancelCurOp = 7,
    // Get the platform authenticator API version.<1> Callers can
    // use the version to identify what features are available on the
    // OS so that caller can decide whether or not a request can be
    // fulfilled.
    CtapCborRpcCommandApiVersion = 8
}

#[derive(Deserialize)]
pub enum WebAuthnRequestType {
    // This command is used to create a new credential for
    // an account for a relying party (registration phase).
    // This is done once per account.
    CtapCborCmdMakeCredential = 1,
    // Used to authenticate the user and sign the client
    // data using the key created previously during the
    // registration phase. This is also called the
    // authenticate phase. The command is exercised
    // multiple times after the registration phase.
    CtapCborCmdGetAssertion = 2,
}

#[derive(Deserialize)]
pub struct WebauthnRequestFlags(u32);

bitflags! {
    impl WebauthnRequestFlags: u32 {
        // Set to indicate the request and response will use
        // U2F. The provider should use the U2F device
        // interface instead of the CTAP interface.
        const CTAPCLT_U2F_FLAG = 0x00020000;
        // Set to indicate to first try CTAP messages and
        // protocol. If CTAP fails, use U2F messages.
        const CTAPCLT_DUAL_FLAG = 0x00040000;
        // Set to force the use of a client pin for
        // CTAPCBOR_CMD_MAKE_CREDENTIAL.
        const CTAPCLT_CLIENT_PIN_REQUIRED_FLAG = 0x00100000;
        // When set for a login get assertion, allows user
        // verification (UV) get assertions to select the
        // credential.
        const CTAPCLT_SELECT_CREDENTIAL_ALLOW_UV_FLAG = 0x00008000;
        // Set to require user verification.
        const CTAPCLT_UV_REQUIRED_FLAG = 0x00400000;
        // Set to indicate user verification is preferred.
        const CTAPCLT_UV_PREFERRED_FLAG = 0x00800000;
        // Indicates that user verification is not required.
        const CTAPCLT_UV_NOT_REQUIRED_FLAG = 0x01000000;
        // Set to enable the hmac-secret extension for a
        // CTAPCBOR_CMD_MAKE_CREDENTIAL request.
        const CTAPCLT_HMAC_SECRET_EXTENSION_FLAG = 0x04000000;
        // Set to force the U2F version 2 interface to be used.
        const CTAPCLT_FORCE_U2F_V2_FLAG = 0x08000000;
    }
}
