#[cfg(test)]
mod file_open_test;
mod bprm_committed_creds_test;
mod sched_process_exec_test;
mod resources;
mod blob_test;
mod utils {
    use anyhow::{bail, Context, Result};
    use tempfile;
    use tempfile::{NamedTempFile, Builder};
    use rand::{distr::Alphanumeric, Rng};
    use std::os::unix::fs::PermissionsExt;
    use std::io::Write;
    use std::process::Command;
    pub(super) async fn run_script(prefix_len: usize, suffix: &str, content: &str) -> Result<()> {
        let mut rng = rand::rng();
        let name: String = rng.sample_iter(Alphanumeric).take(prefix_len).map(char::from).collect();
        run_script_with_name(name.as_str(), suffix, content).await
    }

    pub(super) async fn run_script_with_name(prefix: &str, suffix: &str, content: &str) -> Result<()> {
        let mut file = Builder::new()
            .prefix(prefix)
            .suffix(suffix)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempfile()?;
        write!(file, "{0}", content).context("error writing temp file")?;
        let exit = async_process::Command::new(file.path()).status().await?;
        if exit.success() {
            Ok(())
        } else {
            bail!("error executing script {:?}", exit.code())
        }
    }
}