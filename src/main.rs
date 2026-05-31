mod database;
mod model;

use database::{Database, ObservationRow};
use eframe::egui;
use std::sync::mpsc::{Receiver, Sender};
use std::io::{BufRead, BufReader};
use std::collections::HashSet;
use std::fs::File;

const DB_PATH: &str = "audit.db";

enum Msg {
    Progress { lines: usize, parsed: usize },
    Done {
        inserted: usize,
        skipped: usize,
        cross_matches: Vec<ObservationRow>,
        ips_in_file: usize,
    },
    Error(String),
}

#[derive(PartialEq)]
enum Tab {
    Import,
    Search,
    ImportAndMatch,
}

struct App {
    db: Database,
    tab: Tab,
    import_path: Option<String>,
    busy: bool,
    rx: Option<Receiver<Msg>>,
    progress_lines: usize,
    progress_parsed: usize,
    status: String,
    search_query: String,
    search_results: Vec<ObservationRow>,
    cross_results: Vec<ObservationRow>,
    db_count: i64,
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let db = Database::open(DB_PATH)?;
        let db_count = db.count().unwrap_or(0);
        Ok(App {
            db,
            tab: Tab::Import,
            import_path: None,
            busy: false,
            rx: None,
            progress_lines: 0,
            progress_parsed: 0,
            status: String::new(),
            search_query: String::new(),
            search_results: Vec::new(),
            cross_results: Vec::new(),
            db_count,
        })
    }

    fn start_import(&mut self, path: String, also_match: bool, ctx: egui::Context) {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.busy = true;
        self.progress_lines = 0;
        self.progress_parsed = 0;
        self.status = "Working...".into();
        std::thread::spawn(move || {
            let result = run_import(&path, also_match, &tx, &ctx);
            if let Err(e) = result {
                let _ = tx.send(Msg::Error(format!("{e:#}")));
                ctx.request_repaint();
            }
        });
    }

    fn poll_worker(&mut self) {

    }
}

fn run_import(
    path: &str,
    also_match: bool,
    tx: &Sender<Msg>,
    ctx: &egui::Context,
) -> anyhow::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut db = Database::open(DB_PATH)?;
    let mut batch: Vec<model::Observation> = Vec::with_capacity(10_000);
    let mut lines = 0usize;
    let mut parsed = 0usize;
    let mut skipped = 0usize;
    let mut inserted = 0usize;
    let mut file_ips: HashSet<String> = HashSet::new();
    for line in reader.lines() {
        let line = line?;
        lines += 1;
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
        if batch.len() >= 10_000 {
            inserted += db.import(&batch)?;
            batch.clear();
            let _ = tx.send(Msg::Progress { lines, parsed });
            ctx.request_repaint();
        }
    }
    if !batch.is_empty() {
        inserted += db.import(&batch)?;
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
        ips_in_file: file_ips.len(),
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
                ui.separator();
                ui.label(format!("DB Rows: {}", self.db_count));
            });
        });

        egui::TopBottomPanel::bottom("tabs").show(ctx, |ui| {
            if self.busy {
                ui.label(format!(
                    "Working... {} lines read, {} parsed",
                    self.progress_lines,
                    self.progress_parsed
                ));
            } else if !self.status.is_empty() {
                ui.label(&self.status);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Import => self.ui_import(ui, ctx, false),
            Tab::ImportAndMatch => self.ui_import(ui, ctx, true),
            Tab::Search => self.ui_search(ui),
        });
    }
}

impl App {
    fn ui_import(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, also_match:bool) {}

    fn ui_search(&mut self, ui: &mut egui::Ui) {}
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