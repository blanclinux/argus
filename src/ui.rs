use crate::cli::ListArgs;
use crate::model::PortEntry;
use crate::util;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, BorderType, Clear, Paragraph, Row, Table, TableState};
use ratatui::Terminal;
use std::io;
use std::time::{Duration, Instant};

const PALETTE_BG: Color = Color::Rgb(15, 18, 24);
const PALETTE_PANEL: Color = Color::Rgb(24, 28, 36);
const PALETTE_BORDER: Color = Color::Rgb(46, 52, 64);
const PALETTE_ACCENT: Color = Color::Rgb(88, 196, 220);
const PALETTE_MUTED: Color = Color::Rgb(120, 130, 150);
const PALETTE_OK: Color = Color::Rgb(90, 200, 120);
const PALETTE_WARN: Color = Color::Rgb(230, 190, 80);
const PALETTE_DANGER: Color = Color::Rgb(230, 90, 90);
const PALETTE_PAUSED: Color = Color::Rgb(180, 140, 230);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey { Port, Pid, Process, Status }

impl SortKey {
    fn next(self) -> Self {
        match self { SortKey::Port => SortKey::Pid, SortKey::Pid => SortKey::Process, SortKey::Process => SortKey::Status, SortKey::Status => SortKey::Port }
    }
    fn label(self) -> &'static str {
        match self { SortKey::Port => "port", SortKey::Pid => "pid", SortKey::Process => "process", SortKey::Status => "status" }
    }
}

struct App {
    entries: Vec<PortEntry>,
    filtered_idx: Vec<usize>,
    selected: usize,
    table_state: TableState,
    search: String,
    searching: bool,
    sort: SortKey,
    show_detail: bool,
    confirm_kill: Option<u32>,
    armed: bool,
    message: Option<(String, Instant)>,
    all: bool,
    node_only: bool,
    interval: Duration,
    last_scan: Instant,
}

impl App {
    fn new(interval: u64) -> Self {
        let mut a = Self {
            entries: Vec::new(),
            filtered_idx: Vec::new(),
            selected: 0,
            table_state: TableState::default(),
            search: String::new(),
            searching: false,
            sort: SortKey::Port,
            show_detail: false,
            confirm_kill: None,
            armed: false,
            message: None,
            all: false,
            node_only: false,
            interval: Duration::from_secs(interval.max(1)),
            last_scan: Instant::now() - Duration::from_secs(10),
        };
        a.scan();
        a
    }

    fn scan(&mut self) {
        let args = ListArgs {
            json: false,
            all: self.all,
            node: self.node_only,
            port: None,
            proto: "all".into(),
            interval: self.interval.as_secs(),
        };
        match crate::cli::collect_entries(&args) {
            Ok(mut entries) => {
                match self.sort {
                    SortKey::Port => entries.sort_by_key(|e| (e.local_port, e.pid)),
                    SortKey::Pid => entries.sort_by_key(|e| e.pid),
                    SortKey::Process => entries.sort_by(|a, b| a.process_name.cmp(&b.process_name)),
                    SortKey::Status => entries.sort_by_key(|e| e.status.label()),
                }
                self.entries = entries;
                self.apply_filter();
                self.last_scan = Instant::now();
            }
            Err(e) => {
                self.message = Some((format!("scan error: {e}"), Instant::now()));
            }
        }
    }

    fn apply_filter(&mut self) {
        let q = self.search.to_lowercase();
        self.filtered_idx = self.entries.iter().enumerate().filter(|(_, e)| {
            if q.is_empty() { return true; }
            let hay = format!("{} {} {} {} {}", e.local_port, e.process_name, e.image_path, e.service_name.clone().unwrap_or_default(), e.kind.label()).to_lowercase();
            hay.contains(&q)
        }).map(|(i, _)| i).collect();
        if self.selected >= self.filtered_idx.len() && !self.filtered_idx.is_empty() {
            self.selected = self.filtered_idx.len() - 1;
        }
        self.table_state.select(if self.filtered_idx.is_empty() { None } else { Some(self.selected) });
    }

    fn selected_entry(&self) -> Option<&PortEntry> {
        self.filtered_idx.get(self.selected).map(|&i| &self.entries[i])
    }

    fn next(&mut self) {
        if self.filtered_idx.is_empty() { return; }
        self.selected = (self.selected + 1).min(self.filtered_idx.len() - 1);
        self.table_state.select(Some(self.selected));
    }

    fn prev(&mut self) {
        if self.filtered_idx.is_empty() { return; }
        self.selected = self.selected.saturating_sub(1);
        self.table_state.select(Some(self.selected));
    }

    fn maybe_auto_refresh(&mut self) {
        if self.last_scan.elapsed() >= self.interval { self.scan(); }
    }
}

pub fn run_tui(_cli: crate::cli::Cli) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(2);

    loop {
        app.maybe_auto_refresh();
        terminal.draw(|f| draw(f, &mut app))?;

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if k.code == KeyCode::Char('q') && !app.searching && app.confirm_kill.is_none() && !app.show_detail { break; }

                    if app.searching {
                        match k.code {
                            KeyCode::Esc => { app.searching = false; }
                            KeyCode::Enter => { app.searching = false; }
                            KeyCode::Backspace => { app.search.pop(); app.apply_filter(); }
                            KeyCode::Char(c) => { app.search.push(c); app.apply_filter(); }
                            _ => {}
                        }
                        continue;
                    }

                    if let Some(pid) = app.confirm_kill {
                        match k.code {
                            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => { app.confirm_kill = None; app.armed = false; }
                            KeyCode::Char('y') | KeyCode::Char('Y') => { app.armed = true; }
                            KeyCode::Enter if app.armed => {
                                let msg = crate::actions::kill::kill_pid(pid, false);
                                app.message = Some((msg, Instant::now()));
                                app.confirm_kill = None;
                                app.armed = false;
                                app.scan();
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if app.show_detail {
                        match k.code {
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('d') => app.show_detail = false,
                            _ => {}
                        }
                        continue;
                    }

                    match k.code {
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.prev(),
                        KeyCode::Char('/') => { app.searching = true; }
                        KeyCode::Char('s') => { app.sort = app.sort.next(); app.scan(); }
                        KeyCode::Char('r') => app.scan(),
                        KeyCode::Char('a') => { app.all = !app.all; app.scan(); }
                        KeyCode::Char('n') => { app.node_only = !app.node_only; app.scan(); }
                        KeyCode::Enter | KeyCode::Char('d') => { if app.selected_entry().is_some() { app.show_detail = true; } }
                        KeyCode::Char('x') | KeyCode::Delete => { if let Some(e) = app.selected_entry() { app.confirm_kill = Some(e.pid); app.armed = false; } }
                        KeyCode::Char('c') => { app.message = Some(("copy: use CLI --json".into(), Instant::now())); }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw(f: &mut ratatui::Frame, app: &mut App) {
    let area = f.area();
    f.render_widget(ratatui::widgets::Block::default().style(ratatui::style::Style::default().bg(PALETTE_BG)), area);

    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(2)]).split(area);

    let title = Line::from(vec![
        Span::styled("argus", Style::default().fg(PALETTE_ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("  port & process inspector  ", Style::default().fg(PALETTE_MUTED)),
        Span::styled(format!("sort: {}", app.sort.label()), Style::default().fg(PALETTE_MUTED)),
        Span::styled(format!("   refresh: {}s", app.interval.as_secs()), Style::default().fg(PALETTE_MUTED)),
        Span::styled(if app.all { "   [all]" } else { "   [listeners]" }, Style::default().fg(PALETTE_MUTED)),
        Span::styled(if app.node_only { "  [node]" } else { "" }, Style::default().fg(PALETTE_MUTED)),
    ]);
    let search_line = if app.searching {
        Line::from(vec![Span::styled("search: ", Style::default().fg(PALETTE_ACCENT)), Span::styled(app.search.clone(), Style::default().fg(Color::White)), Span::styled("█", Style::default().fg(PALETTE_ACCENT))])
    } else if !app.search.is_empty() {
        Line::from(vec![Span::styled(format!("filter: {}", app.search), Style::default().fg(PALETTE_MUTED))])
    } else {
        Line::from(vec![Span::styled("keys: ↑↓/jk move  / search  s sort  r refresh  a all  n node  Enter details  x kill  q quit", Style::default().fg(PALETTE_MUTED))])
    };
    let header = Paragraph::new(vec![title, search_line]).block(Block::default().borders(Borders::BOTTOM).border_type(BorderType::Rounded).border_style(Style::default().fg(PALETTE_BORDER)));
    f.render_widget(header, chunks[0]);

    let header_cells = ["PORT","PROTO","STATE","PID","PROCESS","KIND","SERVICE","STARTED","STATUS"].iter().map(|h| Span::styled(*h, Style::default().fg(PALETTE_ACCENT).add_modifier(Modifier::BOLD)));
    let header_row = Row::new(header_cells).height(1).bottom_margin(0);

    let rows: Vec<Row> = app.filtered_idx.iter().map(|&i| {
        let e = &app.entries[i];
        let status_color = match e.status { crate::model::Status::Active => PALETTE_OK, crate::model::Status::Dead => PALETTE_DANGER, crate::model::Status::Stale => PALETTE_WARN, crate::model::Status::Paused => PALETTE_PAUSED, crate::model::Status::Unknown => PALETTE_MUTED };
        Row::new(vec![
            ratatui::widgets::Cell::from(e.local_port.to_string()),
            ratatui::widgets::Cell::from(e.protocol.to_string()),
            ratatui::widgets::Cell::from(e.state.map(|s| s.to_string()).unwrap_or_else(|| "-".into())),
            ratatui::widgets::Cell::from(e.pid.to_string()),
            ratatui::widgets::Cell::from(util::truncate(&e.process_name, 20)),
            ratatui::widgets::Cell::from(e.kind.label()),
            ratatui::widgets::Cell::from(util::truncate(e.service_name.as_deref().unwrap_or("-"), 16)),
            ratatui::widgets::Cell::from(util::truncate(e.start_time.as_deref().unwrap_or("-"), 16)),
            ratatui::widgets::Cell::from(e.status.to_string()).style(Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ])
    }).collect();

    let widths = [Constraint::Length(6), Constraint::Length(6), Constraint::Length(8), Constraint::Length(7), Constraint::Length(20), Constraint::Length(9), Constraint::Length(16), Constraint::Length(16), Constraint::Length(8)];
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(PALETTE_BORDER)).title(Span::styled(format!(" {} entries ", app.filtered_idx.len()), Style::default().fg(PALETTE_MUTED))))
        .row_highlight_style(Style::default().bg(PALETTE_PANEL).add_modifier(Modifier::BOLD))
        .highlight_symbol("▸ ");
    f.render_stateful_widget(table, chunks[1], &mut app.table_state);

    let footer_text = if let Some((msg, ts)) = &app.message {
        if ts.elapsed() < Duration::from_secs(4) { msg.clone() } else { app.message = None; format!("updated {}", simple_now()) }
    } else { format!("updated {}  •  {} total", simple_now(), app.entries.len()) };
    let footer = Paragraph::new(Line::from(Span::styled(footer_text, Style::default().fg(PALETTE_MUTED)))).block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(PALETTE_BORDER)));
    f.render_widget(footer, chunks[2]);

    if app.show_detail { if let Some(e) = app.selected_entry().cloned() { render_detail(f, area, &e); } }
    if let Some(pid) = app.confirm_kill { render_confirm(f, area, pid, app.armed); }
}

fn render_detail(f: &mut ratatui::Frame, area: Rect, e: &PortEntry) {
    let rect = centered_rect(70, 70, area);
    f.render_widget(Clear, rect);
    let block = Block::default().title(Span::styled(" Port detail ", Style::default().fg(PALETTE_ACCENT).add_modifier(Modifier::BOLD))).borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(PALETTE_BORDER)).style(Style::default().bg(PALETTE_PANEL));
    let lines = vec![
        Line::from(vec![Span::styled("Port:        ", Style::default().fg(PALETTE_MUTED)), Span::raw(format!("{}", e.local_port))]),
        Line::from(vec![Span::styled("Protocol:    ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.protocol.to_string())]),
        Line::from(vec![Span::styled("State:       ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.state.map(|s| s.to_string()).unwrap_or_else(|| "-".into()))]),
        Line::from(vec![Span::styled("Status:      ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.status.to_string())]),
        Line::from(vec![Span::styled("Kind:        ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.kind.label())]),
        Line::from(vec![Span::styled("PID:         ", Style::default().fg(PALETTE_MUTED)), Span::raw(format!("{}", e.pid))]),
        Line::from(vec![Span::styled("Process:     ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.process_name.clone())]),
        Line::from(vec![Span::styled("Image:       ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.image_path.clone())]),
        Line::from(vec![Span::styled("Command:     ", Style::default().fg(PALETTE_MUTED)), Span::raw(util::truncate(&e.command_line, 80))]),
        Line::from(vec![Span::styled("Started:     ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.start_time.clone().unwrap_or_else(|| "-".into()))]),
        Line::from(vec![Span::styled("Memory:      ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.memory_kb.map(util::format_bytes).unwrap_or_else(|| "-".into()))]),
        Line::from(vec![Span::styled("Service:     ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.service_name.clone().unwrap_or_else(|| "-".into()))]),
        Line::from(vec![Span::styled("Svc status:  ", Style::default().fg(PALETTE_MUTED)), Span::raw(e.service_status.clone().unwrap_or_else(|| "-".into()))]),
        Line::from(vec![Span::styled("Suspended:   ", Style::default().fg(PALETTE_MUTED)), Span::raw(format!("{}", e.suspended))]),
        Line::from(""),
        Line::from(Span::styled("Esc/Enter to close", Style::default().fg(PALETTE_MUTED))),
    ];
    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, rect);
}

fn render_confirm(f: &mut ratatui::Frame, area: Rect, pid: u32, armed: bool) {
    let rect = centered_rect(50, 30, area);
    f.render_widget(Clear, rect);
    let block = Block::default().title(Span::styled(" Confirm kill ", Style::default().fg(PALETTE_DANGER).add_modifier(Modifier::BOLD))).borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(PALETTE_DANGER)).style(Style::default().bg(PALETTE_PANEL));
    let mut lines = vec![Line::from(format!("Terminate process PID {}?", pid)), Line::from(""), Line::from("This cannot be undone."), Line::from("")];
    if armed {
        lines.push(Line::from(Span::styled("Armed — press Enter to confirm, Esc to cancel", Style::default().fg(PALETTE_DANGER).add_modifier(Modifier::BOLD))));
    } else {
        lines.push(Line::from(Span::styled("Press Y to arm, then Enter to confirm; N/Esc cancel", Style::default().fg(PALETTE_MUTED))));
    }
    let para = Paragraph::new(lines).alignment(Alignment::Center).block(block);
    f.render_widget(para, rect);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage((100 - percent_y) / 2), Constraint::Percentage(percent_y), Constraint::Percentage((100 - percent_y) / 2)]).split(r);
    Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage((100 - percent_x) / 2), Constraint::Percentage(percent_x), Constraint::Percentage((100 - percent_x) / 2)]).split(popup_layout[1])[1]
}

fn simple_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}", secs)
}
