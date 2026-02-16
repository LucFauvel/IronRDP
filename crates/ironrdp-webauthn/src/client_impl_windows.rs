use alloc::string::ToString;
use alloc::vec::Vec;

use ironrdp_pdu::{PduError, PduErrorKind, PduResult};
use tracing::{error, info, warn};
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::{
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNFreeAssertion,
    WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber,
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_CREDENTIALS, WEBAUTHN_EXTENSIONS, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};

use crate::pdu::{
    encode_ctap_response, parse_ctap_request, CtapGetAssertionResponse, CtapMakeCredentialResponse,
    CtapRequest, CtapResponse, DeviceInfo, PublicKeyCredentialDescriptor, RpcCommand,
    WebAuthnChannelRequest, WebAuthnOperationResponseMap, WebAuthnResponse, WebAuthnResponseData,
};

const WEBAUTHN_API_VERSION_1: u32 = 1;
const WEBAUTHN_API_CURRENT_VERSION: u32 = 7;

pub fn handle_webauthn_request(req: WebAuthnChannelRequest) -> PduResult<WebAuthnResponse> {
    info!("WebAuthn request received: command={:?}, flags=0x{:08x}, timeout={}ms",
          req.rpc_command(), req.flags, req.timeout_ms);

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
            info!("Handling WebAuthn operation");
            let result = handle_webauthn_operation(req);
            match &result {
                Ok(resp) => info!("WebAuthn operation succeeded, hresult=0x{:08x}", resp.hresult),
                Err(e) => error!("WebAuthn operation failed: {:?}", e),
            }
            result
        }
        RpcCommand::Iuvpaa => {
            let result = unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() };

            let available = match result {
                Ok(val) => val.as_bool(),
                Err(e) => {
                    warn!("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable failed: {:?}", e);
                    let version = unsafe { WebAuthNGetApiVersionNumber() };
                    version >= WEBAUTHN_API_VERSION_1
                }
            };

            Ok(WebAuthnResponse {
                hresult: 0,
                data: WebAuthnResponseData::Iuvpaa(available),
            })
        }
        RpcCommand::CancelCurrentOp => {
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

fn handle_webauthn_operation(req: WebAuthnChannelRequest) -> PduResult<WebAuthnResponse> {
    let ctap_command = req.ctap_webauthn_command().ok_or_else(|| {
        error!("Missing CTAP command byte in request");
        PduError::new("WebAuthnClient", PduErrorKind::Other {
            description: "Missing CTAP command byte",
        })
    })?;

    let ctap_payload = req.ctap_payload().ok_or_else(|| {
        error!("Missing CTAP payload in request");
        PduError::new("WebAuthnClient", PduErrorKind::Other {
            description: "Missing CTAP payload",
        })
    })?;

    info!("CTAP command=0x{:02x}, payload size={} bytes", u8::from(ctap_command), ctap_payload.len());
    info!("CTAP payload (first 200 bytes): {}", hex::encode(&ctap_payload[..ctap_payload.len().min(200)]));

    let ctap_request = parse_ctap_request(ctap_command, ctap_payload).map_err(|e| {
        error!("Failed to parse CTAP request: {}", e);
        error!("Full CTAP payload hex: {}", hex::encode(ctap_payload));
        PduError::new("WebAuthnClient", PduErrorKind::Other {
            description: "CTAP parse error",
        })
    })?;

    info!("Parsed CTAP request: {:?}", ctap_request);

    let ctap_response = match ctap_request {
        CtapRequest::MakeCredential(make_cred_req) => handle_make_credential(make_cred_req, &req)?,
        CtapRequest::GetAssertion(get_assertion_req) => handle_get_assertion(get_assertion_req, &req)?,
    };

    let response_bytes = encode_ctap_response(ctap_response).map_err(|e| {
        error!("Failed to encode CTAP response: {}", e);
        PduError::new("WebAuthnClient", PduErrorKind::Other {
            description: "CTAP encode error",
        })
    })?;

    let mut response_raw = vec![0x00];
    response_raw.extend_from_slice(&response_bytes);

    info!("CTAP response encoded: {} bytes (including status byte)", response_raw.len());

    let response_map = WebAuthnOperationResponseMap {
        device_info: Some(DeviceInfo {
            max_msg_size: Some(1200),
            max_serialized_large_blob_array: Some(1024),
            provider_type: Some("Platform".to_string()),
            provider_name: Some("Windows WebAuthn".to_string()),
            device_path: None,
            manufacturer: Some("Microsoft".to_string()),
            product: Some("Windows Hello".to_string()),
            aa_guid: None,
        }),
        resident_key: None,
        uv_status: None,
        uv_retries: None,
        status: 0,
        response_raw,
    };

    info!("Sending WebAuthn operation response");

    Ok(WebAuthnResponse {
        hresult: 0,
        data: WebAuthnResponseData::WebAuthn(response_map),
    })
}

fn handle_make_credential(
    req: crate::pdu::CtapMakeCredentialRequest,
    channel_req: &WebAuthnChannelRequest,
) -> PduResult<CtapResponse> {
    info!("MakeCredential for RP: {}", req.rp.id);

    let rp_id = to_wide_string(&req.rp.id);
    let rp_name = req.rp.name.as_ref().map(|s| to_wide_string(s));
    let user_name = req.user.name.as_ref().map(|s| to_wide_string(s));
    let user_display_name = req.user.display_name.as_ref().map(|s| to_wide_string(s));
    let pk_type = to_wide_string("public-key");
    let hash_alg = to_wide_string("SHA-256");

    let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        pwszId: PCWSTR(rp_id.as_ptr()),
        pwszName: PCWSTR(rp_name.as_ref().map_or(core::ptr::null(), |s| s.as_ptr())),
        pwszIcon: PCWSTR::null(),
    };

    let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        cbId: req.user.id.len() as u32,
        pbId: req.user.id.as_ptr() as *mut u8,
        pwszName: PCWSTR(user_name.as_ref().map_or(core::ptr::null(), |s| s.as_ptr())),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: PCWSTR(user_display_name.as_ref().map_or(core::ptr::null(), |s| s.as_ptr())),
    };

    let cose_params: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = req
        .pub_key_cred_params
        .iter()
        .map(|param| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_API_CURRENT_VERSION,
            pwszCredentialType: PCWSTR(pk_type.as_ptr()),
            lAlg: param.alg,
        })
        .collect();

    let cose_params_list = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: cose_params.len() as u32,
        pCredentialParameters: cose_params.as_ptr() as *mut _,
    };

    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        cbClientDataJSON: req.client_data_hash.len() as u32,
        pbClientDataJSON: req.client_data_hash.as_ptr() as *mut u8,
        pwszHashAlgId: PCWSTR(hash_alg.as_ptr()),
    };

    let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        dwTimeoutMilliseconds: channel_req.timeout_ms,
        CredentialList: WEBAUTHN_CREDENTIALS::default(),
        Extensions: WEBAUTHN_EXTENSIONS::default(),
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        bRequireResidentKey: BOOL::from(false),
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
        dwAttestationConveyancePreference: 0,
        dwFlags: 0,
        pCancellationId: core::ptr::null_mut(),
        pExcludeCredentialList: core::ptr::null_mut(),
        dwEnterpriseAttestation: 0,
        dwLargeBlobSupport: 0,
        bPreferResidentKey: BOOL::from(false),
        bBrowserInPrivateMode: BOOL::from(false),
        pLinkedDevice: core::ptr::null_mut(),
        cbJsonExt: 0,
        pbJsonExt: core::ptr::null_mut(),
        bEnablePrf: BOOL::from(false),
    };

    if let Some(params) = &channel_req.web_authn_params {
        if let Some(attachment) = params.attachment_enum() {
            options.dwAuthenticatorAttachment = match attachment {
                crate::pdu::AuthenticatorAttachment::Any => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                crate::pdu::AuthenticatorAttachment::Platform => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                crate::pdu::AuthenticatorAttachment::CrossPlatform => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            };
        }

        if let Some(uv) = params.user_verification_enum() {
            options.dwUserVerificationRequirement = match uv {
                crate::pdu::UserVerificationRequirement::Any => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
                crate::pdu::UserVerificationRequirement::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                crate::pdu::UserVerificationRequirement::Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
                crate::pdu::UserVerificationRequirement::Discouraged => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                }
            };
        }

        if params.require_resident.unwrap_or(false) {
            options.bRequireResidentKey = BOOL::from(true);
        }
    }

    let hwnd = HWND(
        channel_req
            .web_authn_params
            .as_ref()
            .map(|p| p.window_handle as isize as *mut _)
            .unwrap_or(core::ptr::null_mut()),
    );

    let attestation = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &rp_info,
            &user_info,
            &cose_params_list,
            &client_data,
            Some(&options),
        )
    };

    let attestation = match attestation {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("WebAuthNAuthenticatorMakeCredential failed: {:?}", e);
            return Err(PduError::new("WebAuthnClient", PduErrorKind::Other {
                description: "MakeCredential failed",
            }));
        }
    };

    let attestation_ref = unsafe { &*attestation };

    let ctap_response = CtapMakeCredentialResponse {
        fmt: "packed".to_string(),
        auth_data: unsafe {
            core::slice::from_raw_parts(
                attestation_ref.pbAuthenticatorData,
                attestation_ref.cbAuthenticatorData as usize,
            )
            .to_vec()
        },
        att_stmt: ciborium::Value::Null,
    };

    unsafe {
        WebAuthNFreeCredentialAttestation(Some(attestation));
    }

    Ok(CtapResponse::MakeCredential(ctap_response))
}

fn handle_get_assertion(
    req: crate::pdu::CtapGetAssertionRequest,
    channel_req: &WebAuthnChannelRequest,
) -> PduResult<CtapResponse> {
    info!("GetAssertion for RP: {}", req.rp_id);

    let rp_id = to_wide_string(&req.rp_id);
    let hash_alg = to_wide_string("SHA-256");

    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        cbClientDataJSON: req.client_data_hash.len() as u32,
        pbClientDataJSON: req.client_data_hash.as_ptr() as *mut u8,
        pwszHashAlgId: PCWSTR(hash_alg.as_ptr()),
    };

    let mut options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_API_CURRENT_VERSION,
        dwTimeoutMilliseconds: channel_req.timeout_ms,
        CredentialList: WEBAUTHN_CREDENTIALS::default(),
        Extensions: WEBAUTHN_EXTENSIONS::default(),
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
        dwFlags: 0,
        pwszU2fAppId: PCWSTR::null(),
        pbU2fAppId: core::ptr::null_mut(),
        pCancellationId: core::ptr::null_mut(),
        pAllowCredentialList: core::ptr::null_mut(),
        dwCredLargeBlobOperation: 0,
        cbCredLargeBlob: 0,
        pbCredLargeBlob: core::ptr::null_mut(),
        pHmacSecretSaltValues: core::ptr::null_mut(),
        bBrowserInPrivateMode: BOOL::from(false),
        pLinkedDevice: core::ptr::null_mut(),
        bAutoFill: BOOL::from(false),
        cbJsonExt: 0,
        pbJsonExt: core::ptr::null_mut(),
    };

    if let Some(params) = &channel_req.web_authn_params {
        if let Some(uv) = params.user_verification_enum() {
            options.dwUserVerificationRequirement = match uv {
                crate::pdu::UserVerificationRequirement::Any => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
                crate::pdu::UserVerificationRequirement::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                crate::pdu::UserVerificationRequirement::Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
                crate::pdu::UserVerificationRequirement::Discouraged => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                }
            };
        }
    }

    let hwnd = HWND(
        channel_req
            .web_authn_params
            .as_ref()
            .map(|p| p.window_handle as isize as *mut _)
            .unwrap_or(core::ptr::null_mut()),
    );

    let assertion = unsafe {
        WebAuthNAuthenticatorGetAssertion(hwnd, PCWSTR(rp_id.as_ptr()), &client_data, Some(&options))
    };

    let assertion = match assertion {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("WebAuthNAuthenticatorGetAssertion failed: {:?}", e);
            return Err(PduError::new("WebAuthnClient", PduErrorKind::Other {
                description: "GetAssertion failed",
            }));
        }
    };

    let assertion_ref = unsafe { &*assertion };

    let ctap_response = CtapGetAssertionResponse {
        credential: if !assertion_ref.Credential.pbId.is_null() {
            Some(PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: unsafe {
                    core::slice::from_raw_parts(
                        assertion_ref.Credential.pbId,
                        assertion_ref.Credential.cbId as usize,
                    )
                    .to_vec()
                },
                transports: None,
            })
        } else {
            None
        },
        auth_data: unsafe {
            core::slice::from_raw_parts(
                assertion_ref.pbAuthenticatorData,
                assertion_ref.cbAuthenticatorData as usize,
            )
            .to_vec()
        },
        signature: unsafe {
            core::slice::from_raw_parts(assertion_ref.pbSignature, assertion_ref.cbSignature as usize).to_vec()
        },
        user: None,
        number_of_credentials: None,
    };

    unsafe {
        WebAuthNFreeAssertion(assertion as *const _);
    }

    Ok(CtapResponse::GetAssertion(ctap_response))
}

fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}
