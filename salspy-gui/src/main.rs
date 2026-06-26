use salspy_core::database::{Database, DbSpec, ObservationRow};
use salspy_core::import::{ImportOutcome, ImportProgress, run_import};
use salspy_core::settings::{Settings, compose_db_path, compose_postgres_connection};

use eframe::egui;
use eframe::glow::Context;
use std::sync::mpsc::{Receiver, Sender};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;
use std::thread::spawn;
use std::sync::mpsc::channel;
use rfd::FileDialog;

enum Msg {
    Progress(ImportProgress),
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

#[derive(PartialEq, Clone, Copy)]
enum Backend {
    Sqlite,
    Postgres,
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
    known_actions: Vec<String>,
    selected_actions: HashSet<String>,
    db_count: i64,
    safe_writes: bool,
    batch_size: usize,
    confirm_clear: bool,
    backend: Backend,
    active_backend: Backend,
    db_folder: String,
    db_name: String,
    postgres_host: String,
    postgres_port: String,
    postgres_user: String,
    postgres_password: String,
    postgres_dbname: String,
    last_saved: Settings,
}

impl Backend {
    fn label(&self) -> &'static str {
        match self {
            Backend::Sqlite => "SQLite",
            Backend::Postgres => "PostgreSQL",
        }
    }
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let cfg = Settings::load();
        let postgres_password = Settings::load_password();
        let backend = match cfg.backend.as_str() {
            "sqlite" => Backend::Sqlite,
            "postgres" => Backend::Postgres,
            _ => Backend::Sqlite,
        };
        let spec = match backend {
            Backend::Sqlite => DbSpec::Sqlite {
                path: compose_db_path(&cfg.db_folder, &cfg.db_name),
                safe_writes: cfg.safe_writes,
            },
            Backend::Postgres => {
                let port = cfg.postgres_port.trim().parse().unwrap_or(5432);
                DbSpec::Postgres {
                    host: cfg.postgres_host.clone(),
                    port,
                    user: cfg.postgres_user.clone(),
                    password: postgres_password.clone(),
                    dbname: cfg.postgres_dbname.clone(),
                }
            }
        };
        let (mut db, active_backend, status) = match Database::open(&spec) {
            Ok(db) => (db, backend, String::new()),
            Err(e) => {
                let fallback = DbSpec::Sqlite {
                    path: compose_db_path(&cfg.db_folder, &cfg.db_name),
                    safe_writes: cfg.safe_writes,
                };
                let db = Database::open(&fallback)?;
                (db, Backend::Sqlite, format!("Saved backend failed, opened SQLite: {e:#}"))
            }
        };
        let db_count = db.count().unwrap_or(0);
        let known_actions = db.distinct_actions().unwrap_or_default();
        let last_saved = cfg.clone();
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
            status,
            search_query: String::new(),
            search_results: Vec::new(),
            cross_results: Vec::new(),
            db_count,
            safe_writes: cfg.safe_writes,
            batch_size: cfg.batch_size,
            confirm_clear: false,
            known_actions,
            selected_actions: HashSet::new(),
            backend,
            active_backend,
            db_folder: cfg.db_folder,
            db_name: cfg.db_name,
            postgres_host: cfg.postgres_host,
            postgres_port: cfg.postgres_port,
            postgres_user: cfg.postgres_user,
            postgres_password,
            postgres_dbname: cfg.postgres_dbname,
            last_saved,
        })
    }

    fn start_import(&mut self, paths: Vec<String>, also_match: bool, ctx: egui::Context) {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = channel();
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
        let batch_size = self.batch_size;
        let actions: Vec<String> = self.selected_actions.iter().cloned().collect();
        let spec = match self.current_spec() {
            Ok(s) => s,
            Err(e) => {
                self.status = e;
                self.busy = false;
                self.rx = None;
                return;
            }
        };
        spawn(move || {
            let progress_tx = tx.clone();
            let progress_ctx = ctx.clone();
            let outcome = run_import(
                &paths,
                also_match,
                batch_size,
                &spec,
                &actions,
                &cancel,
                &|p: &ImportProgress| {
                    let _ = progress_tx.send(Msg::Progress(p.clone()));
                    progress_ctx.request_repaint();
                },
            );
            let msg = match outcome {
                Ok(ImportOutcome::Complete {
                    inserted,
                    skipped,
                    cross_matches,
                    ips_in_file,
                }) => Msg::Done {
                    inserted,
                    skipped,
                    cross_matches,
                    ips_in_file,
                },
                Ok(ImportOutcome::Aborted { inserted }) => Msg::Aborted { inserted },
                Err(e) => Msg::Error(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn poll_worker(&mut self) {
        let mut done = false;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Progress(p) => {
                        self.progress_bytes_done = p.bytes_done;
                        self.progress_bytes_total = p.bytes_total;
                        self.progress_parsed = p.parsed;
                        self.progress_skipped = p.skipped;
                        self.progress_written = p.written;
                        self.progress_file_index = p.file_index;
                        self.progress_file_count = p.file_count;
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
                        self.known_actions = self.db.distinct_actions().unwrap_or_default();
                        done = true;
                    }
                    Msg::Aborted {
                        inserted
                    } => {
                        self.status = format!("Stopped [{inserted} written]");
                        self.db_count = self.db.count().unwrap_or(self.db_count);
                        self.known_actions = self.db.distinct_actions().unwrap_or_default();
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
        let actions: Vec<String> = self.selected_actions.iter().cloned().collect();
        match self.db.search_ip(&self.search_query, &actions) {
            Ok(rows) => {
                self.status = format!("{} matching", rows.len());
                self.search_results = rows;
            }
            Err(e) => self.status = format!("Error: {e:#}"),
        }
    }

    fn current_spec(&self) -> Result<DbSpec, String> {
        match self.backend {
            Backend::Sqlite => Ok(DbSpec::Sqlite {
                path: compose_db_path(&self.db_folder, &self.db_name),
                safe_writes: self.safe_writes,
            }),
            Backend::Postgres => {
                let port: u16 = self.postgres_port.trim().parse().map_err(|_| format!("Invalid port: '{}'", self.postgres_port))?;
                Ok(DbSpec::Postgres {
                    host: self.postgres_host.trim().to_string(),
                    port,
                    user: self.postgres_user.trim().to_string(),
                    password: self.postgres_password.clone(),
                    dbname: self.postgres_dbname.trim().to_string(),
                })
            }
        }
    }

    fn current_settings(&self) -> Settings {
        Settings {
            backend: match self.backend {
                Backend::Sqlite => "sqlite".to_string(),
                Backend::Postgres => "postgres".to_string(),
            },
            db_folder: self.db_folder.clone(),
            db_name: self.db_name.clone(),
            safe_writes: self.safe_writes,
            batch_size: self.batch_size,
            postgres_host: self.postgres_host.clone(),
            postgres_port: self.postgres_port.clone(),
            postgres_user: self.postgres_user.clone(),
            postgres_dbname: self.postgres_dbname.clone(),
        }
    }

    fn autosave_if_changed(&mut self) {
        let now = self.current_settings();
        if now != self.last_saved {
            match now.save() {
                Ok(()) => self.last_saved = now,
                Err(e) => self.status = e,
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.busy {
            self.poll_worker();
            ctx.request_repaint();
        }

        self.autosave_if_changed();

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Import, "Import");
                ui.selectable_value(&mut self.tab, Tab::Search, "Search");
                ui.selectable_value(&mut self.tab, Tab::ImportAndMatch, "Import and X-ref");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
                ui.separator();
                ui.label(format!("Rows: {}", self.db_count));
                ui.separator();
                let current = match self.active_backend {
                    Backend::Sqlite => format!("SQLite: {}", compose_db_path(&self.db_folder, &self.db_name)),
                    Backend::Postgres => format!("Postgres: {}@{}/{}", self.postgres_user, self.postgres_host, self.postgres_dbname),
                };
                ui.label(current).on_hover_text("Active DB");
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

    fn on_exit(&mut self, _gl: Option<&Context>) {
        let now = self.current_settings();
        if now != self.last_saved {
            let _ = now.save();
        }
        if self.active_backend == Backend::Postgres {
            let _ = Settings::save_password(&self.postgres_password);
        }
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
                .id_salt("file_list")
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
        if also_match {
            self.ui_action_filter(ui);
        }
        let can_run = !self.import_paths.is_empty() && !self.busy;
        if ui.add_enabled(can_run, egui::Button::new("Import")).clicked() {
            self.cross_results.clear();
            let paths = self.import_paths.clone();
            self.start_import(paths, also_match, ctx.clone());
        }
        if also_match && !self.cross_results.is_empty() {
            ui.separator();
            ui.label("Existing users with matching IPs:");
            results_table(ui, "search_results", &self.cross_results);
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
        self.ui_action_filter(ui);
        if ui.button("Apply filter").clicked() {
            self.run_search();
        }
        ui.separator();
        results_table(ui, "search_results", &self.search_results);
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Database backend");
            egui::ComboBox::from_id_salt("backend_select")
                .selected_text(self.backend.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.backend, Backend:: Sqlite, Backend::Sqlite.label());
                    ui.selectable_value(&mut self.backend, Backend::Postgres, Backend::Postgres.label());
                });
        });
        ui.add_space(8.0);

        match self.backend {
            Backend::Sqlite => {
                ui.strong("SQLite settings");
                ui.add_space(4.0);

                ui.label("SQLite DB Location");
                ui.horizontal(|ui| {
                    if ui.button("Choose directory...").clicked() {
                        if let Some(dir) = FileDialog::new().pick_folder() {
                            self.db_folder = dir.display().to_string();
                        }
                    }
                    let shown = if self.db_folder.is_empty() {
                        "(working directory)"
                    } else {
                        self.db_folder.as_str()
                    };
                    ui.monospace(shown).on_hover_text(&self.db_folder);
                });
                ui.horizontal(|ui| {
                    ui.label("DB name");
                    ui.text_edit_singleline(&mut self.db_name);
                });
                ui.add_space(4.0);
                ui.checkbox(&mut self.safe_writes, "Safe writes").on_hover_text("Enable synchronised writing (you should probably enable this)");
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("Apply / open").clicked() && !self.busy {
                        self.reopen_db();
                    }
                    let preview = compose_db_path(&self.db_folder, &self.db_name);
                    ui.monospace(preview);
                });
            }
            Backend::Postgres => {
                ui.group(|ui| {
                    ui.strong("PostgreSQL settings");
                    ui.add_space(4.0);

                    egui::Grid::new("postgres_settings_grid")
                        .num_columns(2)
                        .spacing([8.0, 6.0])
                        .show(ui, |ui| {
                            ui.label("Host");
                            ui.text_edit_singleline(&mut self.postgres_host);
                            ui.end_row();

                            ui.label("Port");
                            ui.text_edit_singleline(&mut self.postgres_port);
                            ui.end_row();

                            ui.label("User");
                            ui.text_edit_singleline(&mut self.postgres_user);
                            ui.end_row();

                            ui.label("Password");
                            ui.add(egui::TextEdit::singleline(&mut self.postgres_password).password(true));
                            ui.end_row();

                            ui.label("Database");
                            ui.text_edit_singleline(&mut self.postgres_dbname);
                            ui.end_row();
                        });

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button("Apply / connect").clicked() && !self.busy {
                            self.reopen_db();
                        }

                        let masked = compose_postgres_connection(
                            &self.postgres_host,
                            &self.postgres_port,
                            &self.postgres_user,
                            if self.postgres_password.is_empty() { "" } else { "********" },
                            &self.postgres_dbname
                        );
                        ui.monospace(masked);
                    });
                });
            }
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Batch size");
            ui.add(
                egui::DragValue::new(&mut self.batch_size).range(1..=1_000_000).speed(1.0),
            );
            if ui.small_button("-").clicked() && self.batch_size > 1 {
                self.batch_size -= 1;
            }
            if ui.small_button("+").clicked() && self.batch_size < 1_000_000 {
                self.batch_size += 1;
            }
        });
        ui.add_space(8.0);
        if !self.confirm_clear {
            if ui.button("Clear DB").clicked() && !self.busy {
                self.confirm_clear = true;
            }
        } else {
            ui.horizontal(|ui| {
                ui.label("Delete ALL rows?");
                if ui.button("Yes").clicked() {
                    match self.db.clear() {
                        Ok(()) => {
                            self.db_count = self.db.count().unwrap_or(0);
                            self.known_actions = self.db.distinct_actions().unwrap_or_default();
                            self.search_results.clear();
                            self.cross_results.clear();
                            self.selected_actions.clear();
                            self.status = "DB cleared".into();
                        }
                        Err(e) => self.status = format!("Clear failed: {e:#}"),
                    }
                    self.confirm_clear = false;
                }
                if ui.button("Cancel").clicked() {
                    self.confirm_clear = false;
                }
            });
        }
    }

    fn ui_action_filter(&mut self, ui: &mut egui::Ui) {
        if self.known_actions.is_empty() {
            return;
        }

        egui::CollapsingHeader::new(format!(
            "Actions ({} selected)",
            if self.selected_actions.is_empty() {
                "all".to_string()
            } else {
                self.selected_actions.len().to_string()
            }
        ))
            .id_salt("action_filter")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button("All").clicked() {
                        self.selected_actions = self.known_actions.iter().cloned().collect();
                    }
                    if ui.small_button("None").clicked() {
                        self.selected_actions.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .id_salt("action_filter_scroll")
                    .max_height(160.0)
                    .show(ui, |ui| {
                        for action in &self.known_actions {
                            let mut on = self.selected_actions.contains(action);
                            if ui.checkbox(&mut on, action).changed() {
                                if on {
                                    self.selected_actions.insert(action.clone());
                                } else {
                                    self.selected_actions.remove(action);
                                }
                            }
                        }
                    })
            });
    }

    fn reopen_db(&mut self) {
        let spec = match self.current_spec() {
            Ok(s) => s,
            Err(e) => { self.status = e; return; }
        };
        match Database::open(&spec) {
            Ok(mut db) => {
                let count = db.count().unwrap_or(0);
                let actions = db.distinct_actions().unwrap_or_default();
                self.db = db;
                self.db_count = count;
                self.known_actions = actions;
                self.search_results.clear();
                self.cross_results.clear();
                self.selected_actions.clear();
                self.active_backend = self.backend;
                let mut pw_warning = String::new();
                if self.backend == Backend::Postgres {
                    if let Err(e) = Settings::save_password(&self.postgres_password) {
                        pw_warning = format!(" (password not saved: {e})");
                    }
                }
                self.status = match self.backend {
                    Backend::Sqlite => format!("Opened SQLite: {}", compose_db_path(&self.db_folder, &self.db_name)),
                    Backend::Postgres => format!("Connected: {}@{}/{}{pw_warning}", self.postgres_user, self.postgres_host, self.postgres_dbname),
                };
            }
            Err(e) => {
                self.status = format!("Connect failed: {e:#}");
            }
        }
    }
}

fn results_table(ui: &mut egui::Ui, id: &str, rows: &[ObservationRow]) {
    egui::ScrollArea::both().id_salt(id).show(ui, |ui| {
        egui::Grid::new(id)
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
        "salSPY",
        native_options,
        Box::new(|_cc| {
            let app = App::new().expect("failed to open db");
            Ok(Box::new(app))
        }),
    )
}