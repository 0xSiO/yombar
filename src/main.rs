use std::{collections::VecDeque, env, fs, path::PathBuf};

use clap::{ArgAction, Parser, Subcommand};
use color_eyre::eyre::bail;
use fuser::MountOption;
use tracing::instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use yombar::{
    fs::{fuse::FuseFileSystem, DirEntry, EncryptedFileSystem, FileKind, Translator},
    Result, Vault,
};

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
    /// Translate between cleartext paths and encrypted paths
    Translate {
        /// Path to encrypted vault directory
        vault_path: PathBuf,
        /// Path to translate
        path: PathBuf,
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
                MountOption::FSName(String::from("yombar")),
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
        Command::Translate { vault_path, path } => {
            let password = rpassword::prompt_password("Password: ")?;
            let vault = Vault::open(&vault_path, password)?;
            let translator = Translator::new(&vault);

            // If the provided path is within the vault, we'll try to decrypt it
            if path.exists() && path.canonicalize()?.starts_with(vault_path.canonicalize()?) {
                tracing::debug!("encrypted path detected, attempting decryption");

                let path = path.canonicalize()?;
                let fs = EncryptedFileSystem::new(&vault);
                let mut queue: VecDeque<(PathBuf, DirEntry)> = VecDeque::new();
                queue.extend(fs.dir_entries("")?.into_iter().collect::<Vec<_>>());

                // Breadth-first search of the filesystem
                while let Some((cleartext_path, entry)) = queue.pop_front() {
                    let dir_id = translator.get_dir_id(cleartext_path.parent().unwrap())?;
                    let ciphertext_path =
                        translator.get_ciphertext_path(&cleartext_path, &dir_id)?;
                    tracing::debug!(?dir_id, ?cleartext_path, ?ciphertext_path);

                    if ciphertext_path == path {
                        println!("{}", cleartext_path.display());
                        return Ok(());
                    } else if entry.kind == FileKind::Directory {
                        queue.extend(
                            fs.dir_entries(cleartext_path)?
                                .into_iter()
                                .collect::<Vec<_>>(),
                        );
                    }
                }

                bail!("failed to find matching cleartext path");
            } else {
                tracing::debug!("cleartext path detected, attempting encryption");

                // First, try assuming it's a file
                let dir_id = translator.get_dir_id(&path)?;
                let file_path = translator.get_ciphertext_path(&path, &dir_id)?;

                tracing::debug!(?file_path, "looking for matching file path");
                if file_path.exists() {
                    println!("{}", file_path.display());
                    return Ok(());
                }

                // Next, try assuming it's a directory
                let parent_dir_id = translator.get_dir_id(path.parent().unwrap())?;
                let dir_path = translator.get_ciphertext_path(&path, &parent_dir_id)?;

                tracing::debug!(?dir_path, "looking for matching directory path");
                if dir_path.exists() {
                    println!("{}", dir_path.display());
                    return Ok(());
                }

                bail!("failed to find matching encrypted path");
            }
        }
    };

    Ok(())
}
