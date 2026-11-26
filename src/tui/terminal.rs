//! Terminal lifecycle management and RAII restoration guard.
//!
//! Ensures raw mode, alternate screen, and cursor visibility are reliably
//! restored across normal exit, error returns, cancellation, and panics.

use std::io::{self, Stdout};
use std::sync::Once;

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

static PANIC_HOOK_INSTALLED: Once = Once::new();

/// RAII wrapper around the Crossterm terminal that restores terminal state on [`Drop`].
pub struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active: bool,
}

impl TerminalSession {
    /// Enters raw mode and the alternate screen, installing a one-time panic hook
    /// that restores the terminal before unwinding.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if raw mode or the alternate screen cannot be initialised.
    pub fn enter() -> io::Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(mut terminal) => {
                let _ = terminal.clear();
                Ok(Self {
                    terminal,
                    active: true,
                })
            }
            Err(err) => {
                restore_terminal_best_effort();
                Err(err)
            }
        }
    }

    /// Borrows the underlying Ratatui [`Terminal`] for frame drawing.
    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    /// Explicitly restores the terminal before dropping.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if terminal restoration fails.
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let _ = self.terminal.show_cursor();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        disable_raw_mode()
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            restore_terminal_best_effort();
        }
    }
}

fn install_panic_hook() {
    PANIC_HOOK_INSTALLED.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal_best_effort();
            prev(info);
        }));
    });
}

/// Best-effort restoration of raw mode, alternate screen, and cursor visibility.
pub fn restore_terminal_best_effort() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, crossterm::cursor::Show);
}
