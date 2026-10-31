//! Windows installation media: read UDF ISOs and write bootable UDF/El Torito ISOs.

pub mod reader;
pub mod udf;
pub mod writer;

pub use reader::{Entry, UdfReader};
pub use writer::{WriteOptions, write_iso};

/// Default boot images of Windows installation media, relative to the media root.
pub const BIOS_BOOT: &str = "boot/etfsboot.com";
pub const UEFI_BOOT: &str = "efi/microsoft/boot/efisys.bin";
pub const UEFI_BOOT_NOPROMPT: &str = "efi/microsoft/boot/efisys_noprompt.bin";
