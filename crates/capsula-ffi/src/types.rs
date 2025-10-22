//! FFI types and enums

use std::{
    ffi::CString,
    os::raw::{c_char, c_uchar, c_uint},
    ptr,
};

// ============================================================================
// Types and Enums
// ============================================================================

/// Supported key algorithms
#[repr(C)]
pub enum CapsulaAlgorithm {
    Curve25519 = 0,
    Rsa2048 = 1,
    P256 = 2,
}

/// FFI Error codes
#[repr(C)]
pub enum CapsulaError {
    Success = 0,
    InvalidInput = 1,
    KeyGenerationFailed = 2,
    SigningFailed = 3,
    ExportFailed = 4,
    ImportFailed = 5,
    IoError = 6,
    InternalError = 7,
}

/// FFI Result structure for returning data and error status
#[repr(C)]
pub struct CapsulaResult {
    pub error_code: CapsulaError,
    pub data: *mut c_uchar,
    pub data_len: c_uint,
    pub error_message: *mut c_char,
}

impl CapsulaResult {
    pub fn success(data: Vec<u8>) -> Self {
        let mut boxed_data = data.into_boxed_slice();
        let data_ptr = boxed_data.as_mut_ptr();
        let data_len = boxed_data.len() as c_uint;
        std::mem::forget(boxed_data); // Prevent automatic deallocation

        Self {
            error_code: CapsulaError::Success,
            data: data_ptr,
            data_len,
            error_message: ptr::null_mut(),
        }
    }

    pub fn error(code: CapsulaError, message: &str) -> Self {
        let c_message = CString::new(message)
            .unwrap_or_else(|_| CString::new("Failed to create error message").unwrap());

        Self {
            error_code: code,
            data: ptr::null_mut(),
            data_len: 0,
            error_message: c_message.into_raw(),
        }
    }

    /// Helper function to create a boxed success result
    pub fn success_boxed(data: Vec<u8>) -> *mut CapsulaResult {
        Box::into_raw(Box::new(Self::success(data)))
    }

    /// Helper function to create a boxed error result  
    pub fn error_boxed(code: CapsulaError, message: &str) -> *mut CapsulaResult {
        Box::into_raw(Box::new(Self::error(code, message)))
    }
}
