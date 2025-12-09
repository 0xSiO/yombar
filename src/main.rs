use std::{collections::VecDeque, env, path::PathBuf};

use clap::{ArgAction, Parser, Subcommand};
use color_eyre::eyre::bail;
use tracing::instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use yombar::{
    Result,
    fs::{DirEntry, EncryptedFileSystem, FileKind, Translator},
    util::SecretString,
    vault::Vault,
};

#[derive(Debug, Parser)]
#[command(version)]
/// yombar: A simpler, faster, and more lightweight implementation of Cryptomator using Rust.
pub struct Args {
    /// Enable verbose output (can be specified multiple times)
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
    /// Mount a vault as a virtual filesystem using FUSE
    #[cfg(unix)]
    Mount {
        /// Path to encrypted vault directory
        vault_path: PathBuf,
        /// Path to directory in which to mount the virtual filesystem
        mount_point: PathBuf,
        /// Mount vault as a read-only filesystem
        #[arg(short, long)]
        read_only: bool,
    },
    // /// Serve a vault from a local WebDAV server
    // #[cfg(feature = "webdav")]
    // Serve {
    //     /// Path to encrypted vault directory
    //     vault_path: PathBuf,
    //     /// Only allow read-only HTTP methods
    //     #[arg(short, long)]
    //     read_only: bool,
    // },
    /// Translate between cleartext paths and encrypted paths
    Translate {
        /// Path to encrypted vault directory
        vault_path: PathBuf,
        /// Path to translate
        path: PathBuf,
    },
}

#[instrument]
fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    // Safety: std::env::set_var is safe to call in a single-threaded program.
    unsafe {
        env::set_var(
            "RUST_LOG",
            match args.verbose {
                0 => "info",
                1 => "debug",
                _ => "trace",
            },
        );
    }

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
            let password = SecretString::from(rpassword::prompt_password("Set password: ")?);
            Vault::create(vault_path, password)?;
        }
        #[cfg(unix)]
        Command::Mount {
            vault_path,
            mount_point,
            read_only,
        } => {
            use fuser::MountOption;
            use yombar::fs::fuse::FuseFileSystem;

            if !vault_path.exists() {
                bail!("failed to find vault at provided path");
            }

            let password = SecretString::from(rpassword::prompt_password("Password: ")?);
            let vault = Vault::open(&vault_path, password)?;

            let mut mount_options = vec![
                MountOption::FSName(String::from("yombar")),
                MountOption::DefaultPermissions,
            ];

            if read_only {
                mount_options.push(MountOption::RO);
            }

            std::fs::create_dir_all(&mount_point)?;

            fuser::mount2(
                FuseFileSystem::new(EncryptedFileSystem::new(&vault)),
                &mount_point,
                &mount_options,
            )?;
        }
        // #[cfg(feature = "webdav")]
        // Command::Serve {
        //     vault_path,
        //     read_only,
        // } => {
        //     use axum::routing::any;
        //     use dav_server::{DavHandler, DavMethodSet, memls::MemLs};
        //     use yombar::fs::webdav::WebDavFileSystem;
        //
        //     if !vault_path.exists() {
        //         bail!("failed to find vault at provided path");
        //     }
        //
        //     let password = rpassword::prompt_password("Password: ")?;
        //     let vault = Vault::open(&vault_path, password)?;
        //
        //     let vault: &'static Vault = Box::leak(Box::new(vault));
        //     let webdav_fs = WebDavFileSystem::new(EncryptedFileSystem::new(vault));
        //     let permitted_methods = if read_only {
        //         DavMethodSet::WEBDAV_RO
        //     } else {
        //         DavMethodSet::WEBDAV_RW
        //     };
        //
        //     let webdav_server = DavHandler::builder()
        //         .methods(permitted_methods)
        //         .filesystem(Box::new(webdav_fs))
        //         .locksystem(MemLs::new())
        //         .build_handler();
        //
        //     let rt = tokio::runtime::Runtime::new()?;
        //     rt.block_on(async move {
        //         let listener = tokio::net::TcpListener::bind("0.0.0.0:4918").await.unwrap();
        //
        //         tracing::info!(addr = %listener.local_addr().unwrap(), "starting WebDAV server");
        //         axum::serve(
        //             listener,
        //             any(|req| async move { webdav_server.handle(req).await }),
        //         )
        //         .await
        //         .unwrap();
        //     });
        // }
        Command::Translate { vault_path, path } => {
            if !vault_path.exists() {
                bail!("failed to find vault at provided path");
            }

            let password = SecretString::from(rpassword::prompt_password("Password: ")?);
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
