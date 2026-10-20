//! Minimal Windows UAC helper used only for the final removal step of an
//! explicitly requested quarantine action.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_FAILED};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

const HELPER_ARGUMENT: &str = "--elevated-quarantine-delete";
const EXIT_NOT_ELEVATED: i32 = 10;
const EXIT_INVALID_REQUEST: i32 = 11;
const EXIT_REMOVE_FAILED: i32 = 12;

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Quotes one Windows command-line argument according to CommandLineToArgvW
/// rules. This keeps spaces and trailing backslashes in file paths intact.
fn quote_argument(value: &OsStr) -> OsString {
    let source: Vec<u16> = value.encode_wide().collect();
    let mut quoted = Vec::with_capacity(source.len() + 2);
    quoted.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in source {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            quoted.push(unit);
        } else {
            quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            quoted.push(unit);
        }
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    quoted.push(b'"' as u16);
    use std::os::windows::ffi::OsStringExt;
    OsString::from_wide(&quoted)
}

fn process_is_elevated() -> bool {
    let mut token = std::ptr::null_mut();
    // SAFETY: Windows initializes `token` on success. All handles obtained here
    // are closed, and the output buffer has the exact TOKEN_ELEVATION size.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Handles the private helper mode before Tauri and the single-instance plugin
/// start. Returns `None` for a normal app launch.
pub fn run_helper_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(HELPER_ARGUMENT)) {
        return None;
    }
    if !process_is_elevated() {
        return Some(EXIT_NOT_ELEVATED);
    }
    let Some(path) = arguments.next() else { return Some(EXIT_INVALID_REQUEST) };
    let Some(expected_sha256) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Some(EXIT_INVALID_REQUEST);
    };
    if arguments.next().is_some() {
        return Some(EXIT_INVALID_REQUEST);
    }
    match seccom_engine::quarantine::remove_file_if_hash_matches(Path::new(&path), &expected_sha256) {
        Ok(()) => Some(0),
        Err(_) => Some(EXIT_REMOVE_FAILED),
    }
}

/// Relaunches this executable through the Windows `runas` verb and waits for
/// the narrowly scoped helper operation to finish.
pub fn remove_with_uac(path: &Path, expected_sha256: &str) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| format!("could not resolve SecCorp executable: {error}"))?;
    let parameters = {
        let mut value = OsString::from(HELPER_ARGUMENT);
        value.push(" ");
        value.push(quote_argument(path.as_os_str()));
        value.push(" ");
        value.push(expected_sha256);
        value
    };
    let executable = wide_null(executable.as_os_str());
    let verb = wide_null(OsStr::new("runas"));
    let parameters = wide_null(&parameters);
    // SAFETY: every string is NUL-terminated and remains alive for the call.
    // ShellExecuteExW owns the returned process handle until we close it.
    unsafe {
        let mut execute: SHELLEXECUTEINFOW = std::mem::zeroed();
        execute.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        execute.fMask = SEE_MASK_NOCLOSEPROCESS;
        execute.lpVerb = verb.as_ptr();
        execute.lpFile = executable.as_ptr();
        execute.lpParameters = parameters.as_ptr();
        execute.nShow = SW_HIDE;
        if ShellExecuteExW(&mut execute) == 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(1223) {
                Err("Administrator permission was cancelled; the file was not removed".into())
            } else {
                Err(format!("could not request Administrator permission: {error}"))
            };
        }
        if execute.hProcess.is_null() {
            return Err("Windows did not return the elevated helper process".into());
        }
        let wait = WaitForSingleObject(execute.hProcess, INFINITE);
        if wait == WAIT_FAILED {
            let error = std::io::Error::last_os_error();
            let _ = CloseHandle(execute.hProcess);
            return Err(format!("could not wait for the elevated quarantine operation: {error}"));
        }
        let mut exit_code = 0u32;
        let got_exit_code = GetExitCodeProcess(execute.hProcess, &mut exit_code);
        let error = (got_exit_code == 0).then(std::io::Error::last_os_error);
        let _ = CloseHandle(execute.hProcess);
        if let Some(error) = error {
            return Err(format!("could not read the elevated quarantine result: {error}"));
        }
        match exit_code as i32 {
            0 => Ok(()),
            EXIT_NOT_ELEVATED => Err("Windows did not grant Administrator permission".into()),
            EXIT_INVALID_REQUEST => Err("the elevated quarantine request was invalid".into()),
            EXIT_REMOVE_FAILED => Err("the elevated helper could not verify and remove the file".into()),
            code => Err(format!("the elevated quarantine helper failed with exit code {code}")),
        }
    }
}
