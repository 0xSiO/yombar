use std::{fs::File, path::PathBuf};

use crate::Vault;

#[allow(dead_code)]
pub struct EncryptedFile<'v> {
    vault: &'v Vault,
    actual_dir: PathBuf,
    actual_file: File,
}
