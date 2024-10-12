pub mod crypto;
pub mod fs;
pub mod key;
mod util;
pub mod vault;

pub type Result<T> = color_eyre::Result<T>;
