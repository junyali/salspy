mod database;

use database::{Database, ObservationRow};
use eframe::egui;
use std::sync::mpsc::{Receiver, };

const DB_PATH: &str = "audit.db";

enum Msg {
    Progress { lines: usize, parsed: usize },
    Done {
        inserted: usize,
        skipped: usize,
        cross_matches: Vec<ObservationRow>,
        ips_in_file: usize,
    }
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

    fn poll_worker(&mut self) {

    }
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