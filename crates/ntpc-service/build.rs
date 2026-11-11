//! Embeds the Windows version resource into the exe.
//!
//! Code signing (`SignPath` Foundation) requires the product name to be the
//! project name and the product version to be the same in every build. Both
//! come from the workspace version in the root `Cargo.toml`, so there is one
//! source (docs/releasing.md).
//!
//! The numeric `FILEVERSION` cannot hold a pre-release part such as
//! `alpha.1`. It carries major, minor, patch and 0. The full `SemVer` text is in
//! the `ProductVersion` and `FileVersion` strings.

use std::{env, fs, path::PathBuf};

fn main() {
    // The resource only applies to a Windows exe. A build on another OS skips it.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let num = |name: &str| env::var(name).ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
    let (major, minor, patch) = (
        num("CARGO_PKG_VERSION_MAJOR"),
        num("CARGO_PKG_VERSION_MINOR"),
        num("CARGO_PKG_VERSION_PATCH"),
    );

    let rc = format!(
        r#"#include <winver.h>
VS_VERSION_INFO VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "ProductName", "ntptimeclient-winrs\0"
      VALUE "ProductVersion", "{version}\0"
      VALUE "FileVersion", "{version}\0"
      VALUE "FileDescription", "ntptimeclient-winrs Windows time service\0"
      VALUE "OriginalFilename", "ntptimeclient-winrs.exe\0"
      VALUE "InternalName", "ntptimeclient-winrs\0"
      VALUE "LegalCopyright", "MIT OR Apache-2.0\0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 0x04B0
  END
END
"#
    );
    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("version.rc");
    fs::write(&out, rc).expect("write version.rc");
    embed_resource::compile(&out, embed_resource::NONE)
        .manifest_required()
        .expect("embed the version resource");
    println!("cargo:rerun-if-changed=build.rs");
}
