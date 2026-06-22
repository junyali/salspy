use std::cell::Cell;
use salspy_core::database::{Database, DbSpec, ObservationRow};
use salspy_core::settings::{compose_db_path, Settings};

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use clap::{Parser, Subcommand};
use anyhow::{Result, bail};
use salspy_core::import::{run_import, ImportProgress, ImportOutcome};
use std::fmt::Write as FmtWrite;
use std::io::{stderr, stdin, Write as IoWrite};
use minus::{Pager, page_all};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(
    name = "salspy",
    version,
    about = "Slack Audit Log SPY",
    long_about = "Read and parse Slack Enterprise Grid audit-log exports."
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
    #[command(visible_alias = "i")]
    Import {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<String>,

        #[arg(long)]
        xref: bool,

        #[arg(long, value_delimiter = ',', value_name = "ACTION")]
        actions: Vec<String>,

        #[arg(long, short = 'f')]
        full: bool,
    },

    #[command(visible_alias = "s")]
    Search {
        #[arg(value_name = "IP")]
        ip: String,

        #[arg(long, value_delimiter = ',', value_name = "ACTION")]
        actions: Vec<String>,

        #[arg(long, short = 'f')]
        full: bool,
    },

    #[command(visible_alias = "c")]
    Count,

    #[command(visible_alias = "d")]
    Clear {
        #[arg(long)]
        yes: bool,
    },

    #[command(visible_alias = "a")]
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
fn byte_bar_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) - {msg}").unwrap().progress_chars("█▉▊▋▌▍▎▏ ")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}...", s.chars().take(max.saturating_sub(1)).collect::<String>())
    } else {
        s.to_string()
    }
}

fn write_table(pager: &mut Pager, rows: &[ObservationRow]) -> Result<()> {
    const W_IP: usize = 39;
    const W_USER: usize = 26;
    const W_EMAIL: usize = 32;
    const W_UA: usize = 48;
    const W_JA3: usize = 32;
    const W_HITS: usize = 6;

    let divider = format!(
        "{:-<W_IP$}  {:-<W_USER$}  {:-<W_EMAIL$}  {:-<W_UA$}  {:-<W_JA3$}  {:->W_HITS$}",
        "", "", "", "", "", ""
    );

    writeln!(
        pager,
        "{:<W_IP$}  {:<W_USER$}  {:<W_EMAIL$}  {:<W_UA$}  {:<W_JA3$}  {:>W_HITS$}",
        "IP", "USER (ID)", "EMAIL", "USER AGENT", "JA3", "HITS"
    )?;
    writeln!(pager, "{divider}")?;

    for row in rows {
        let user_col = format!(
            "{} ({})",
            row.user_name.as_deref().unwrap_or("?"),
            &row.user_id,
        );
        writeln!(
            pager,
            "{:<W_IP$}  {:<W_USER$}  {:<W_EMAIL$}  {:<W_UA$}  {:<W_JA3$}  {:>W_HITS$}",
            row.ip,
            truncate(&user_col, W_USER),
            truncate(row.user_email.as_deref().unwrap_or(""), W_EMAIL),
            truncate(row.user_agent.as_deref().unwrap_or(""), W_UA),
            truncate(row.ja3.as_deref().unwrap_or(""), W_JA3),
            row.hits,
        )?;
    }

    writeln!(pager, "{divider}")?;
    writeln!(pager, "{} row(s)", rows.len())?;
    Ok(())
}

fn write_full(pager: &mut Pager, rows: &[ObservationRow]) -> Result<()> {
    for (i, r) in rows.iter().enumerate() {
        writeln!(pager, "--#{}--------------------------", i + 1)?;
        writeln!(pager, "IP:        {}", r.ip)?;
        writeln!(pager, "User:      {} ({})", r.user_name.as_deref().unwrap_or("?"), r.user_id)?;
        writeln!(pager, "Email:     {}", r.user_email.as_deref().unwrap_or(""))?;
        writeln!(pager, "UA:        {}", r.user_agent.as_deref().unwrap_or(""))?;
        writeln!(pager, "JA3:       {}", r.ja3.as_deref().unwrap_or(""))?;
        writeln!(pager, "Hits:      {}", r.hits)?;
        writeln!(pager)?;
    }
    writeln!(pager, "{} row(s)", rows.len())?;
    Ok(())
}

fn page_results(rows: &[ObservationRow], full: bool) -> Result<()> {
    if rows.is_empty() {
        eprintln!("(no results)");
        return Ok(());
    }

    let mut pager = Pager::new();
    let hint = if full { "q to quit, / to search" } else { "q to quit, / to search, --full for complete values" };
    pager.set_prompt(format!("{} result(s) - {hint}", rows.len()))?;

    if full {
        write_full(&mut pager, rows)?;
    } else {
        write_table(&mut pager, rows)?;
    }

    page_all(pager)?;
    Ok(())
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
        Commands::Import { files, xref, actions, full } => {
            let (spec, batch_size) = resolve_spec(&cli)?;
            let cancel = Arc::new(AtomicBool::new(false));
            let last_file_index: Cell<usize> = Cell::new(usize::MAX);
            let current_bar: Cell<Option<ProgressBar>> = Cell::new(None);
            let outcome = run_import(
                files,
                *xref,
                batch_size,
                &spec,
                actions,
                &cancel,
                &|p : &ImportProgress| {
                    if p.file_index != last_file_index.get() {
                        if let Some(old) = current_bar.take() {
                            old.finish_and_clear();
                        }
                        let new_pb = ProgressBar::new(p.bytes_total);
                        new_pb.set_style(byte_bar_style());
                        current_bar.set(Some(new_pb));
                        last_file_index.set(p.file_index);
                    }
                    if let Some(bar) = current_bar.take() {
                        bar.set_position(p.bytes_done);
                        bar.set_message(format!(
                            "file {}/{} | {} written | {} skipped",
                            p.file_index + 1,
                            p.file_count,
                            p.written,
                            p.skipped
                        ));
                        current_bar.set(Some(bar));
                    }
                },
            )?;

            if let Some(bar) = current_bar.into_inner() {
                bar.finish_and_clear();
            }

            match outcome {
                ImportOutcome::Complete { inserted, skipped, cross_matches, ips_in_file } => {
                    eprintln!("Done: {inserted} written, {skipped} skipped");
                    if *xref {
                        eprintln!("  {ips_in_file} unique IPs checked - {} matches", cross_matches.len());
                        if !cross_matches.is_empty() {
                            page_results(&cross_matches, *full)?;
                        }
                    }
                }
                ImportOutcome::Aborted { inserted } => {
                    eprintln!("Aborted: {inserted} written before cancel");
                }
            }
        }

        Commands::Search { ip, actions, full } => {
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            let rows = db.search_ip(ip, actions)?;
            page_results(&rows, *full)?;
        }

        Commands::Count => {
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            println!("{}", db.count()?);
        }

        Commands::Clear { yes } => {
            if !yes {
                let confirms = [
                    "Are you sure? [y/N] ",
                    "Are you really sure? [y/N] ",
                    "Are you absolutely sure? This is irreversible. [y/N] ",
                ];
                for prompt in confirms {
                    eprint!("{prompt}");
                    stderr().flush()?;
                    let mut input = String::new();
                    stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        eprintln!("Aborted");
                        return Ok(());
                    }
                }
            }
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            db.clear()?;
            eprintln!("DB cleared");
        }

        Commands::Actions => {
            let (spec, _) = resolve_spec(&cli)?;
            let mut db = Database::open(&spec)?;
            let actions = db.distinct_actions()?;
            if actions.is_empty() {
                print!("(no actions in database)");
            } else {
                for action in &actions {
                    println!("{action}");
                }
                eprintln!("\n{} distinct action(s)", actions.len());
            }
        }
    }

    Ok(())
}
