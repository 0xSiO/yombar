use anyhow::Result;

pub mod util;
pub mod vault;

fn main() -> Result<()> {
    println!(
        "{:#?}",
        vault::Vault::derive_master_key(String::from("here is a password"))?
    );

    Ok(())
}
