#[cfg(test)]
mod blob_loaders_test;
#[cfg(test)]
mod blob_test;
#[cfg(test)]
mod bprm_committed_creds_test;
#[cfg(test)]
mod file_open_test;
#[cfg(test)]
mod resources;
#[cfg(test)]
mod sched_process_exec_test;

#[cfg(test)]
mod utils {
    use anyhow::{bail, Context, Result};
    use rand::{distr::Alphanumeric, Rng};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile;
    use tempfile::Builder;

    pub(super) fn random_prefix(len: usize) -> String {
        rand::rng()
            .sample_iter(Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub(super) async fn run_script_with_name(
        prefix: &str,
        suffix: &str,
        content: &str,
    ) -> Result<()> {
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
