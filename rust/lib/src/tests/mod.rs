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
    pub(super) fn run_script(scriptname_len: usize, content: &str) -> Result<()> {
        let mut rng = rand::rng();
        let name: String = rng.sample_iter(Alphanumeric).take(scriptname_len).map(char::from).collect();
        run_script_with_name(name.as_str(), content)
    }

    pub(super) fn run_script_with_name(name: &str, content: &str) -> Result<()> {
        let mut file = Builder::new()
            .prefix(name)
            .suffix(".lw_script")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempfile()?;
        write!(file, "{0}", content).context("error writing temp file")?;
        let exit = Command::new(file.path()).status()?;
        if exit.success() {
            Ok(())
        } else {
            bail!("error executing script {:?}", exit.code())
        }
    }
}