use std::process::ExitCode;
use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(
    name = "salspy",
    version,
    about = "salspy",
    long_about = "Slack Audit Log Spy"
)]

struct Cli {
    #[arg(long, global = true, value_name = "BACKEND")]
    backend: Option<String>,

    #[arg(long, global = true, value_name = "DIR")]
    db_folder: Option<String>,

    #[arg(long, global = true, value_name = "FILE")]
    db_name: Option<String>,

    #[arg(long, global = true)]
    no_safe_writes: bool,

    #[arg(long, global = true, value_name = "HOST")]
    postgres_host: Option<String>,

    #[arg(long, global = true, value_name = "PORT")]
    postgres_port: Option<u16>,

    #[arg(long, global = true, value_name = "USER")]
    postgres_user: Option<String>,

    #[arg(long, global = true, value_name = "PASS")]
    postgres_password: Option<String>,

    #[arg(long, global = true, value_name = "DBNAME")]
    postgres_dbname: Option<String>,

    #[arg(long, global = true, value_name = "N")]
    batch_size: Option<usize>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Import {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<String>,

        #[arg(long)]
        xref: bool,

        #[arg(long, value_delimiter = ",", value_name = "ACTION")]
        actions: Vec<String>,
    },
    Search {
        #[arg(value_name = "IP")]
        ip: String,

        #[arg(long, value_delimiter = ",", value_name = "ACTION")]
        actions: Vec<String>,
    },
    Count,
    Clear {
        #[arg(long)]
        yes: bool,
    },
    Actions,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {

}
