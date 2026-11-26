use std::path::Path;

use crate::{command::Cmd, report::Report};

pub fn checks(report: &mut Report, root: &Path) -> Result<(), String> {
    for script in [
        "python3 scripts/check_architecture.py --check",
        "python3 scripts/check_generated_paths.py",
        "python3 scripts/check_compile_policy.py",
        "python3 scripts/check_naming_conventions.py",
    ] {
        let outcome = Cmd::new(script).execute(root)?;
        let failed = outcome.status == "failed";
        println!("[{}] {}", outcome.status, script);
        report.push(outcome);
        if failed {
            return Ok(());
        }
    }
    Ok(())
}

pub fn assure(report: &mut Report, root: &Path) -> Result<(), String> {
    let line = "scripts/assurance/polish.sh";
    let outcome = Cmd::new(line).execute(root)?;
    let failed = outcome.status == "failed";
    println!("[{}] {}", outcome.status, line);
    report.push(outcome);
    if failed {
        return Err("assurance gate failed".to_owned());
    }
    Ok(())
}
