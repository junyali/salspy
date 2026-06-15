use crate::database::{Database, DbSpec, ObservationRow};
use crate::model;
use std::collections::HashSet;
use std::fs::{copy, metadata, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct ImportProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub parsed: usize,
    pub skipped: usize,
    pub written: usize,
    pub file_index: usize,
    pub file_count: usize,
}

#[derive(Debug)]
pub enum ImportOutcome {
    Complete {
        inserted: usize,
        skipped: usize,
        cross_matches: Vec<ObservationRow>,
        ips_in_file: usize,
    },
    Aborted {
        inserted: usize,
    },
}

pub fn run_import(
    paths: &[String],
    also_match: bool,
    batch_size: usize,
    spec: &DbSpec,
    actions: &[String],
    cancel: &Arc<AtomicBool>,
    on_progress: &dyn Fn(&ImportProgress),
) -> anyhow::Result<ImportOutcome> {
    if let DbSpec::Sqlite { path, safe_writes: false } = &spec {
        if Path::new(path).exists() {
            let _ = copy(path, format!("{path}.old"));
        }
    }
    let mut db = Database::open(&spec)?;
    let mut parsed = 0usize;
    let mut skipped = 0usize;
    let mut inserted = 0usize;
    let mut file_ips: HashSet<String> = HashSet::new();
    let file_count = paths.len();

    let mut aborted = false;
    'outer: for (file_index, path) in paths.iter().enumerate() {
        let bytes_total = metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut bytes_done = 0u64;
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut batch: Vec<model::Observation> = Vec::with_capacity(batch_size);

        for line in reader.lines() {
            if cancel.load(Ordering::Relaxed) {
                aborted = true;
                break 'outer;
            }
            let line = line?;
            bytes_done += line.len() as u64 + 1;
            match model::parse_line(&line) {
                Ok(Some(entry)) => {
                    let obs = model::entry_to_observations(&entry);
                    if obs.is_empty() {
                        skipped += 1;
                    } else {
                        parsed += 1;
                        for o in &obs {
                            file_ips.insert(o.ip.clone());
                        }
                        batch.extend(obs);
                    }
                }
                Ok(None) => {}
                Err(_) => skipped += 1,
            }
            if batch.len() >= batch_size {
                inserted += db.import(&batch, cancel)?;
                batch.clear();
                on_progress(&ImportProgress {
                    bytes_done,
                    bytes_total,
                    parsed,
                    skipped,
                    written: inserted,
                    file_index,
                    file_count,
                });
            }
        }
        if !batch.is_empty() {
            inserted += db.import(&batch, cancel)?;
        }
        on_progress(&ImportProgress {
            bytes_done: bytes_total,
            bytes_total,
            parsed,
            skipped,
            written: inserted,
            file_index,
            file_count,
        });
    }

    if aborted {
        return Ok(ImportOutcome::Aborted { inserted });
    }

    let cross_matches = if also_match {
        let ips: Vec<String> = file_ips.iter().cloned().collect();
        db.match_ips(&ips, actions)?
    } else {
        Vec::new()
    };
    Ok(ImportOutcome::Complete {
        inserted,
        skipped,
        cross_matches,
        ips_in_file: file_ips.len(),
    })
}
