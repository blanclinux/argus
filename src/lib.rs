pub mod model;
pub mod util;

#[cfg(any(windows, target_os = "linux"))]
#[cfg(windows)]
pub mod platform;

pub mod ui;
pub mod cli;
pub mod actions;
