use std::io::{self, Write};

pub fn enable_vt() -> bool {
    // Linux terminals support ANSI/VT escape codes natively.
    let _ = io::stdout().flush();
    true
}

#[allow(dead_code)]
pub fn set_color(_attr: u16) {
    // ANSI colors are handled by crossterm/ratatui on Linux.
}
