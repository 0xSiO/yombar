use cryptomator::{
    fs::{fuse::FuseFileSystem, EncryptedFileSystem},
    Result, Vault,
};
use fuser::MountOption;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .without_time()
                .with_file(false),
        )
        .with(tracing_error::ErrorLayer::default())
        .init();

    let _ = Vault::create("./new_vault", String::from("password"));

    let vault = Vault::open("new_vault", String::from("password"))?;

    fuser::mount2(
        FuseFileSystem::new(EncryptedFileSystem::new(&vault)),
        "example",
        &[
            // MountOption::RO,
            MountOption::FSName(String::from("example-fs")),
            MountOption::DefaultPermissions,
        ],
    )?;

    Ok(())
}
