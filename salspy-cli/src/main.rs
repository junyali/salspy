use salspy_core::database::{Database, DbSpec, ObservationRow};
use salspy_core::settings::{compose_db_path, Settings};

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use clap::{Parser, Subcommand};
use anyhow::{Result, bail};
use salspy_core::import::{run_import, ImportProgress};
use std::io::{stderr, stdin};

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

        #[arg(long, value_delimiter = ',', value_name = "ACTION")]
        actions: Vec<String>,
    },
    Search {
        #[arg(value_name = "IP")]
        ip: String,

        #[arg(long, value_delimiter = ',', value_name = "ACTION")]
        actions: Vec<String>,
    },
    Count,
    Clear {
        #[arg(long)]
        yes: bool,
    },
    Actions,
}

fn any_postgres_flag(cli: &Cli) -> bool {
    cli.postgres_host.is_some() || cli.postgres_port.is_some() || cli.postgres_user.is_some() || cli.postgres_password.is_some() || cli.postgres_dbname.is_some()
}

fn resolve_spec(cli: &Cli) -> Result<(DbSpec, usize)> {
    let cfg = Settings::load();
    let postgres_implied = any_postgres_flag(cli);

    let backend: &str = match cli.backend.as_deref() {
        Some("postgres") => "postgres",
        Some("sqlite") => {
            if postgres_implied {
                bail!("");
            }
            "sqlite"
        }
        Some(other) => bail!(""),
        None => {
            if postgres_implied { "postgres" } else { cfg.backend.as_str() }
        }
    };

    let batch_size = cli.batch_size.unwrap_or(cfg.batch_size);

    let spec = match backend {
        "postgres" => {
            let port = cli.postgres_port.unwrap_or_else(|| cfg.postgres_port.trim().parse().unwrap_or(5432));
            DbSpec::Postgres {
                host: cli.postgres_host.clone().unwrap_or(cfg.postgres_host),
                port,
                user: cli.postgres_user.clone().unwrap_or(cfg.postgres_user),
                password: cli.postgres_password.clone().unwrap_or_else(Settings::load_password),
                dbname: cli.postgres_dbname.clone().unwrap_or(cfg.postgres_dbname),
            }
        }
        _ => DbSpec::Sqlite {
            path: compose_db_path(
                cli.db_folder.as_deref().unwrap_or(&cfg.db_folder),
                cli.db_name.as_deref().unwrap_or(&cfg.db_name),
            ),
            safe_writes: !cli.no_safe_writes && cfg.safe_writes,
        },
    };

    Ok((spec, batch_size))
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
    match &cli.command {
        Commands::Import { files, xref, actions } => {
            let (spec, batch_size) = resolve_spec(&cli)?;
            let cancel = Arc::new(AtomicBool::new(false));
            let outcome = run_import(
                files,
                *xref,
                batch_size,
                &spec,
                actions,
                &cancel,
                &|p : &ImportProgress| {},
            )?;
        }

        Commands::Count => {
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            println!("{}", db.count()?);
        }

        Commands::Clear { yes } => {
            if !yes {
                eprint!("Delete ALL rows from DB? [y/N] ");
                stderr().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("Aborted");
                    return Ok(());
                }
            }
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            db.clear()?;
            eprintln!("DB cleared");
        }
    }
}
