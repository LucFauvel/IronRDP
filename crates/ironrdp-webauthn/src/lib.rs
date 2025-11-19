#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub const CHANNEL_NAME: &str = "WebAuthN_Channel";

pub mod client;
#[cfg(all(feature = "std", target_family = "wasm"))]
pub mod client_impl_wasm;
#[cfg(all(feature = "std", windows))]
pub mod client_impl_windows;
pub mod pdu;
pub mod server;

