use std::{env, fs, path::PathBuf};

use clap::{ArgAction, Parser, Subcommand};
use cryptomator::{
    fs::{fuse::FuseFileSystem, EncryptedFileSystem},
    Result, Vault,
};
use fuser::MountOption;
use tracing::instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// Create a new empty vault
    Create {
        /// Path to directory in which to initialize the vault
        vault_path: PathBuf,
    },
    /// Mount a vault as a virtual filesystem
    Mount {
        /// Path to encrypted vault directory
        vault_path: PathBuf,
        /// Path to directory in which to mount the virtual filesystem
        mount_point: PathBuf,
        /// Mount vault as a read-only filesystem
        #[arg(short, long)]
        read_only: bool,
    },
}

#[instrument]
pub fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    env::set_var(
        "RUST_LOG",
        match args.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        },
    );

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

    tracing::debug!(?args);

    match args.cmd {
        Command::Create { vault_path } => {
            let password = rpassword::prompt_password("Set password: ")?;
            Vault::create(vault_path, password)?;
        }
        Command::Mount {
            vault_path,
            mount_point,
            read_only,
        } => {
            let password = rpassword::prompt_password("Password: ")?;
            let vault = Vault::open(&vault_path, password)?;
            let mut options = vec![
                MountOption::FSName(String::from("cryptomator-rs")),
                MountOption::DefaultPermissions,
            ];

            if read_only {
                options.push(MountOption::RO);
            }

            fs::create_dir_all(&mount_point)?;

            // TODO: Maybe spawn in background, wait for exit signal, and drop session
            fuser::mount2(
                FuseFileSystem::new(EncryptedFileSystem::new(&vault)),
                &mount_point,
                &options,
            )?;
        }
    };

    Ok(())
}
