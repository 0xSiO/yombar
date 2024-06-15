use cryptomator::{
    fs::{fuse::FuseFileSystem, EncryptedFileSystem},
    Vault,
};
use fuser::MountOption;

pub fn main() {
    let _ = pretty_env_logger::try_init();

    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac/vault.cryptomator",
        String::from("password"),
    )
    .unwrap();

    fuser::mount2(
        FuseFileSystem::new(EncryptedFileSystem::new(&vault)),
        "example",
        &[
            // MountOption::RO,
            MountOption::FSName(String::from("example-fs")),
        ],
    )
    .unwrap();
}
