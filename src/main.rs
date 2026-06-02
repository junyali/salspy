mod database;
mod model;

use database::{Database, ObservationRow};
use eframe::egui;
use std::sync::mpsc::{Receiver, Sender};
use std::io::{BufRead, BufReader};
use std::collections::HashSet;
use std::fs::{File, copy, metadata};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;

const DB_PATH: &str = "audit.db";

enum Msg {
    Progress {
        bytes_done: u64,
        bytes_total: u64,
        parsed: usize,
        skipped: usize,
        written: usize,
        file_index: usize,
        file_count: usize,
    },
    Done {
        inserted: usize,
        skipped: usize,
        cross_matches: Vec<ObservationRow>,
        ips_in_file: usize,
    },
    Aborted {
        inserted: usize,
    },
    Error(String),
}

#[derive(PartialEq)]
enum Tab {
    Import,
    Search,
    ImportAndMatch,
    Settings,
}

struct App {
    db: Database,
    tab: Tab,
    import_paths: Vec<String>,
    busy: bool,
    rx: Option<Receiver<Msg>>,
    cancel: Arc<AtomicBool>,
    progress_bytes_done: u64,
    progress_bytes_total: u64,
    progress_parsed: usize,
    progress_skipped: usize,
    progress_written: usize,
    progress_file_index: usize,
    progress_file_count: usize,
    status: String,
    search_query: String,
    search_results: Vec<ObservationRow>,
    cross_results: Vec<ObservationRow>,
    db_count: i64,
    safe_writes: bool,
    batch_size: usize,
    confirm_clear: bool,
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let safe_writes = true;
        let db = Database::open(DB_PATH, safe_writes)?;
        let db_count = db.count().unwrap_or(0);
        Ok(App {
            db,
            tab: Tab::Import,
            import_paths: Vec::new(),
            busy: false,
            rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress_bytes_done: 0,
            progress_bytes_total: 0,
            progress_parsed: 0,
            progress_skipped: 0,
            progress_written: 0,
            progress_file_index: 0,
            progress_file_count: 0,
            status: String::new(),
            search_query: String::new(),
            search_results: Vec::new(),
            cross_results: Vec::new(),
            db_count,
            safe_writes,
            batch_size: 10_000,
            confirm_clear: false,
        })
    }

    fn start_import(&mut self, paths: Vec<String>, also_match: bool, ctx: egui::Context) {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.busy = true;
        self.cancel.store(false, Ordering::Relaxed);
        self.progress_bytes_done = 0;
        self.progress_bytes_total = 0;
        self.progress_parsed = 0;
        self.progress_skipped = 0;
        self.progress_written = 0;
        self.progress_file_index = 0;
        self.progress_file_count = paths.len();
        self.status = "Working...".into();

        let cancel = self.cancel.clone();
        let safe_writes = self.safe_writes;
        let batch_size = self.batch_size;
        std::thread::spawn(move || {
            let result = run_import(&paths, also_match, safe_writes, batch_size, &cancel, &tx, &ctx);
            if let Err(e) = result {
                let _ = tx.send(Msg::Error(format!("{e:#}")));
                ctx.request_repaint();
            }
        });
    }

    fn poll_worker(&mut self) {
        let mut done = false;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Progress {
                        bytes_done,
                        bytes_total,
                        parsed,
                        skipped,
                        written,
                        file_index,
                        file_count,
                    } => {
                        self.progress_bytes_done = bytes_done;
                        self.progress_bytes_total = bytes_total;
                        self.progress_parsed = parsed;
                        self.progress_skipped = skipped;
                        self.progress_written = written;
                        self.progress_file_index = file_index;
                        self.progress_file_count = file_count;
                    }
                    Msg::Done {
                        inserted,
                        skipped,
                        cross_matches,
                        ips_in_file
                    } => {
                        let mut s = format!("Done [{inserted} written, {skipped} skipped]");
                        if ips_in_file > 0 {
                            s.push_str(&format!(" - {ips_in_file} IPs checked, {} shared with existing users", cross_matches.len()));
                        }
                        self.status = s;
                        self.cross_results = cross_matches;
                        self.db_count = self.db.count().unwrap_or(self.db_count);
                        done = true;
                    }
                    Msg::Aborted {
                        inserted
                    } => {
                        self.status = format!("Stopped [{inserted} written]");
                        self.db_count = self.db.count().unwrap_or(self.db_count);
                        done = true;
                    }
                    Msg::Error(e) => {
                        self.status = format!("Error: {e}");
                        done = true;
                    }
                }
            }
        }
        if done {
            self.busy = false;
            self.rx = None;
        }
    }

    fn run_search(&mut self) {
        match self.db.search_ip(&self.search_query) {
            Ok(rows) => {
                self.status = format!("{} matching", rows.len());
                self.search_results = rows;
            }
            Err(e) => self.status = format!("Error: {e:#}"),
        }
    }
}

fn run_import(
    paths: &[String],
    also_match: bool,
    safe_writes: bool,
    batch_size: usize,
    cancel: &Arc<AtomicBool>,
    tx: &Sender<Msg>,
    ctx: &egui::Context,
) -> anyhow::Result<()> {
    if !safe_writes && Path::new(DB_PATH).exists() {
        let _ = copy(DB_PATH, format!("{DB_PATH}.old"));
    }
    let mut db = Database::open(DB_PATH, safe_writes)?;
    let mut parsed = 0usize;
    let mut skipped = 0usize;
    let mut inserted = 0usize;
    let mut file_ips: HashSet<String> = HashSet::new();
    let file_count = paths.len();

    let mut aborted = false;
    'outer: for (file_index, path) in paths.iter().enumerate() {
        let bytes_total = metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut bytes_done = 064;
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
                inserted += db.import(&batch)?;
                batch.clear();
                let _ = tx.send(Msg::Progress {
                    bytes_done,
                    bytes_total,
                    parsed,
                    skipped,
                    written: inserted,
                    file_index,
                    file_count,
                });
                ctx.request_repaint();
            }
        }
        if !batch.is_empty() {
            inserted += db.import(&batch)?;
        }
        let _ = tx.send(Msg::Progress {
            bytes_done: bytes_total,
            bytes_total,
            parsed,
            skipped,
            written: inserted,
            file_index,
            file_count
        });
        ctx.request_repaint();
    }

    if aborted {
        tx.send(Msg::Aborted { inserted })?;
        ctx.request_repaint();
        return Ok(());
    }

    let cross_matches = if also_match {
        let ips: Vec<String> = file_ips.iter().cloned().collect();
        db.match_ips(&ips)?
    } else {
        Vec::new()
    };
    tx.send(Msg::Done {
        inserted,
        skipped,
        cross_matches,
        ips_in_file: file_ips.len()
    })?;
    ctx.request_repaint();
    Ok(())
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.busy {
            self.poll_worker();
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Import, "Import");
                ui.selectable_value(&mut self.tab, Tab::Search, "Search");
                ui.selectable_value(&mut self.tab, Tab::ImportAndMatch, "Import and X-ref");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
                ui.separator();
                ui.label(format!("DB Rows: {}", self.db_count));
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            if self.busy {
                let fraction = if self.progress_bytes_total > 0 {
                    self.progress_bytes_done as f32 / self.progress_bytes_total as f32
                } else {
                    0.0
                };
                ui.horizontal(|ui| {
                    ui.label(format!(
                        "File {} of {}",
                        self.progress_file_index + 1,
                        self.progress_file_count
                    ));
                    if ui.button("Stop").clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                });
                ui.add(egui::ProgressBar::new(fraction).show_percentage());
                ui.label(format!("{} parsed | {} skipped | {} written", self.progress_parsed, self.progress_skipped, self.progress_written));
            } else if !self.status.is_empty() {
                ui.label(&self.status);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Import => self.ui_import(ui, ctx, false),
            Tab::ImportAndMatch => self.ui_import(ui, ctx, true),
            Tab::Search => self.ui_search(ui),
            Tab::Settings => self.ui_settings(ui),
        });
    }
}

impl App {
    fn ui_import(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, also_match:bool) {
        if also_match {
            ui.heading("Import a file and X-reference IPs");
            ui.label("Lists every existing user in DB with matching IPs to file");
        } else {
            ui.heading("Import ndjson export");
            ui.label("Store observations from imported log");
        }
        ui.separator();
        if self.busy {
            ui.label("Running...");
        }
        ui.horizontal(|ui| {
            if ui.button("Choose files...").clicked() && !self.busy {
                if let Some(ps) = rfd::FileDialog::new()
                    .add_filter("NDJSON", &["ndjson", "json", "jsonl", "txt"])
                    .pick_files()
                {
                    self.import_paths = ps.iter().map(|p| p.display().to_string()).collect();
                }
            }
            if !self.import_paths.is_empty() {
                ui.label(format!("{} file(s) selected", self.import_paths.len()));
                if ui.button("Clear").clicked() {
                    self.import_paths.clear();
                }
            }
        });
        if !self.import_paths.is_empty() {
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    for p in &self.import_paths {
                        let name = Path::new(p)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| p.clone());
                        let shown = if name.chars().count() > 48 {
                            format!("{}...", name.chars().take(47).collect::<String>())
                        } else {
                            name
                        };
                        ui.monospace(shown).on_hover_text(p);
                    }
                });
        }
        let can_run = !self.import_paths.is_empty();
        if ui.add_enabled(can_run, egui::Button::new("Import")).clicked() {
            self.cross_results.clear();
            let paths = self.import_paths.clone();
            self.start_import(paths, also_match, ctx.clone());
        }
        if also_match && !self.cross_results.is_empty() {
            ui.separator();
            ui.label("Existing users with matching IPs:");
            results_table(ui, &self.cross_results);
        }
    }

    fn ui_search(&mut self, ui: &mut egui::Ui) {
        ui.heading("Search by IP");
        ui.separator();
        ui.horizontal(|ui| {
            let resp = ui.text_edit_singleline(&mut self.search_query);
            let go = ui.button("Search").clicked() || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if go {
                self.run_search();
            }
        });
        ui.separator();
        results_table(ui, &self.search_results);
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();

        ui.checkbox(&mut self.safe_writes, "Safe writes").on_hover_text("Enable synchronised writing (you should probably enable this)");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Batch size");
            ui.add(
                egui::DragValue::new(&mut self.batch_size).range(1..=1_000_000).speed(1.0),
            );
            if ui.small_button("-").clicked() && self.batch_size > 0 {
                self.batch_size -= 1;
            }
            if ui.small_button("+").clicked() && self.batch_size < 1_000_000 {
                self.batch_size += 1;
            }
        });
    }
}

fn results_table(ui: &mut egui::Ui, rows: &[ObservationRow]) {
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("results")
            .striped(true)
            .show(ui, |ui| {
                ui.strong("IP");
                ui.strong("User");
                ui.strong("Email");
                ui.strong("UA");
                ui.strong("JA3");
                ui.strong("Hits");
                ui.end_row();
                for r in rows {
                    ui.monospace(&r.ip);
                    ui.label(format!(
                        "{} ({})",
                        r.user_name.as_deref().unwrap_or("?"),
                        r.user_id
                    ));
                    ui.label(r.user_email.as_deref().unwrap_or(""));
                    ui.label(r.user_agent.as_deref().unwrap_or(""));
                    ui.monospace(r.ja3.as_deref().unwrap_or(""));
                    ui.label(r.hits.to_string());
                    ui.end_row();
                }
            });
    });
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "SALGUI",
        native_options,
        Box::new(|_cc| {
            let app = App::new().expect("failed to open db");
            Ok(Box::new(app))
        }),
    )
}