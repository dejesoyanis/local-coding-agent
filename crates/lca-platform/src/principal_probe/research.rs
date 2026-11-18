//! Separate-user, AppContainer, and VM notes.
//!
//! No account is created. No optional Windows feature is enabled. An AppContainer
//! profile, when the call succeeds, is deleted before this function returns.

#![allow(unsafe_code)]

use std::path::Path;
use std::ptr;

use windows_sys::Win32::Security::FreeSid;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrincipalClass {
    SameUserRestricted,
    SeparateLocalUser,
    AppContainer,
    VirtualMachine,
}

pub(super) fn same_sid_matches(class: PrincipalClass, same_sid: bool) -> bool {
    match class {
        PrincipalClass::SameUserRestricted => same_sid,
        PrincipalClass::SeparateLocalUser
        | PrincipalClass::AppContainer
        | PrincipalClass::VirtualMachine => !same_sid,
    }
}

pub(super) fn investigate() -> String {
    let contract = format!(
        "account_created=0 logon_attempted=0 same_sid_separate={} same_sid_restricted={}",
        if same_sid_matches(PrincipalClass::SeparateLocalUser, true) {
            "accepted"
        } else {
            "rejected"
        },
        if same_sid_matches(PrincipalClass::SameUserRestricted, true) {
            "accepted"
        } else {
            "rejected"
        }
    );
    format!(
        "{contract} {} {} prerequisite=a separate local account, its password, and a profile are not provisioned",
        appcontainer_probe(),
        vm_probe()
    )
}

fn appcontainer_probe() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let name = format!("lca01m{}x{}", std::process::id(), nanos % 1_000_000);
    let wide_name = wide(&name);
    let display = wide("lca-01m");
    let mut sid = ptr::null_mut();
    let created = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            ptr::null(),
            0,
            &mut sid,
        )
    };
    if created != 0 {
        return format!(
            "appcontainer_create={:#x} appcontainer_delete=na appcontainer_launched=0",
            created as u32
        );
    }
    if !sid.is_null() {
        unsafe { FreeSid(sid) };
    }
    let deleted = unsafe { DeleteAppContainerProfile(wide_name.as_ptr()) };
    format!("appcontainer_create=0 appcontainer_delete={deleted:#x} appcontainer_launched=0")
}

fn vm_probe() -> String {
    let vmcompute = Path::new(r"C:\Windows\System32\vmcompute.exe").exists();
    let sandbox = Path::new(r"C:\Windows\System32\WindowsSandbox.exe").exists();
    let vmwp = Path::new(r"C:\Windows\System32\vmwp.exe").exists();
    format!(
        "vmcompute={} sandbox={} vmwp={} vm_started=0",
        u8::from(vmcompute),
        u8::from(sandbox),
        u8::from(vmwp)
    )
}

#[cfg(test)]
mod tests {
    use super::{PrincipalClass, investigate, same_sid_matches};

    #[test]
    fn separate_user_appcontainer_and_vm_are_not_deployed() {
        assert!(same_sid_matches(PrincipalClass::SameUserRestricted, true));
        assert!(!same_sid_matches(PrincipalClass::SeparateLocalUser, true));
        assert!(!same_sid_matches(PrincipalClass::AppContainer, true));
        assert!(!same_sid_matches(PrincipalClass::VirtualMachine, true));
        assert!(same_sid_matches(PrincipalClass::SeparateLocalUser, false));
        let report = investigate();
        assert!(report.contains("account_created=0"), "{report}");
        assert!(report.contains("logon_attempted=0"), "{report}");
        assert!(report.contains("same_sid_separate=rejected"), "{report}");
        assert!(report.contains("vm_started=0"), "{report}");
        assert!(report.contains("appcontainer_launched=0"), "{report}");
        assert!(
            report.contains("appcontainer_create=0 ") || report.contains("appcontainer_create=0x"),
            "{report}"
        );
        if report.contains("appcontainer_create=0 ") {
            assert!(report.contains("appcontainer_delete=0x0"), "{report}");
        }
        let dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target"))
            .join("lca-01m");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("research.txt"), &report);
    }
}
