// TODO: Types that implement Read/Write for:
// - reading cleartext -> ciphertext
// - reading ciphertext -> cleartext
// - writing cleartext -> ciphertext

use std::{fs::File, path::PathBuf};

use crate::Vault;

pub struct EncryptedFile<'v> {
    vault: &'v Vault,
    actual_dir: PathBuf,
    actual_file: File,
}
