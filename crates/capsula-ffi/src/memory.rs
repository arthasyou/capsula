//! Memory management and utility functions

use std::{ffi::CString, os::raw::c_char};

use crate::types::CapsulaResult;

// ============================================================================
// Memory Management
// ============================================================================

/// Free memory allocated by the FFI library
#[no_mangle]
pub extern "C" fn capsula_free_result(result: *mut CapsulaResult) {
    if result.is_null() {
        return;
    }

    unsafe {
        let result = Box::from_raw(result);

        // Free data if present
        if !result.data.is_null() && result.data_len > 0 {
            let data = Vec::from_raw_parts(
                result.data,
                result.data_len as usize,
                result.data_len as usize,
            );
            drop(data);
        }

        // Free error message if present
        if !result.error_message.is_null() {
            let _ = CString::from_raw(result.error_message);
        }
    }
}

/// Free a C string allocated by the FFI library
#[no_mangle]
pub extern "C" fn capsula_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

// ============================================================================
// Version Information
// ============================================================================

/// Get library version string
#[no_mangle]
pub extern "C" fn capsula_get_version() -> *mut c_char {
    let version = env!("CARGO_PKG_VERSION");
    match CString::new(version) {
        Ok(c_version) => c_version.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
