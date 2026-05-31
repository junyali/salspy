mod database;

use database::{Database, ObservationRow};
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