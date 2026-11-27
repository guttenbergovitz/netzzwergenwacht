//! Modal keyboard translation for Zwergenleitstand.
//!
//! Ensures global navigation shortcuts (`1`–`9`, `j`/`k`, `q`, `c`, `/`, etc.)
//! never interfere with text entry in the Launcher URL input or the bottom
//! Search/Filter bar.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::tui::action::UserAction;
use crate::tui::state::{AppState, WorkbenchView};

/// Translates a terminal [`KeyEvent`] into a [`UserAction`] based on the active
/// modal state in [`AppState`].
#[must_use]
pub fn translate_key_event(key: KeyEvent, state: &AppState) -> Option<UserAction> {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return None;
    }

    // Ctrl+C always requests immediate cancellation (if running) or quit.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return Some(UserAction::Quit);
    }

    // 1. Help overlay open: Esc, ?, or q closes Help.
    if state.help_open {
        return match key.code {
            KeyCode::Esc | KeyCode::Char('?' | 'q') => Some(UserAction::ToggleHelp),
            _ => None,
        };
    }

    // 2. Search/filter input bar focused.
    if state.search_focused {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter => Some(UserAction::BackOrClose),
            KeyCode::Backspace => Some(UserAction::InputBackspace),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UserAction::InputClear)
            }
            KeyCode::Char(ch)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                Some(UserAction::InputChar(ch))
            }
            _ => None,
        };
    }

    // 3. Launcher modal open.
    if state.launcher.open {
        let editing_url = state.launcher.focused_field.is_text_field();
        return match key.code {
            KeyCode::Esc => Some(UserAction::BackOrClose),
            KeyCode::Tab | KeyCode::Down => Some(UserAction::MoveDown),
            KeyCode::BackTab | KeyCode::Up => Some(UserAction::MoveUp),
            KeyCode::Enter => Some(UserAction::Activate),
            KeyCode::Left if !editing_url => Some(UserAction::MoveLeft),
            KeyCode::Right if !editing_url => Some(UserAction::MoveRight),
            KeyCode::Char(' ') if !editing_url => Some(UserAction::Activate),
            KeyCode::Backspace if editing_url => Some(UserAction::InputBackspace),
            KeyCode::Char('u') if editing_url && key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some(UserAction::InputClear)
            }
            KeyCode::Char(ch)
                if editing_url
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                Some(UserAction::InputChar(ch))
            }
            KeyCode::Char('?') if !editing_url => Some(UserAction::ToggleHelp),
            KeyCode::Char('q') if !editing_url => Some(UserAction::Quit),
            _ => None,
        };
    }

    // 4. Normal workbench navigation mode.
    match key.code {
        KeyCode::Tab => Some(UserAction::NextView),
        KeyCode::BackTab => Some(UserAction::PrevView),
        KeyCode::Char('1') => Some(UserAction::SelectView(WorkbenchView::Overview)),
        KeyCode::Char('2') => Some(UserAction::SelectView(WorkbenchView::Brigade)),
        KeyCode::Char('3') => Some(UserAction::SelectView(WorkbenchView::Targets)),
        KeyCode::Char('4') => Some(UserAction::SelectView(WorkbenchView::Findings)),
        KeyCode::Char('5') => Some(UserAction::SelectView(WorkbenchView::Evidence)),
        KeyCode::Char('6') => Some(UserAction::SelectView(WorkbenchView::Investigation)),
        KeyCode::Char('7') => Some(UserAction::SelectView(WorkbenchView::Topology)),
        KeyCode::Char('8') => Some(UserAction::SelectView(WorkbenchView::History)),
        KeyCode::Char('9') => Some(UserAction::SelectView(WorkbenchView::System)),
        KeyCode::Char('j') | KeyCode::Down => Some(UserAction::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(UserAction::MoveUp),
        KeyCode::Char('h') | KeyCode::Left => Some(UserAction::MoveLeft),
        KeyCode::Char('l') | KeyCode::Right => Some(UserAction::MoveRight),
        KeyCode::Char('g') | KeyCode::Home => Some(UserAction::FirstItem),
        KeyCode::Char('G') | KeyCode::End => Some(UserAction::LastItem),
        KeyCode::PageUp => Some(UserAction::PageUp),
        KeyCode::PageDown => Some(UserAction::PageDown),
        KeyCode::Enter => Some(UserAction::Activate),
        KeyCode::Esc => Some(UserAction::BackOrClose),
        KeyCode::Char('/') => Some(UserAction::OpenSearch),
        KeyCode::Char('s') => Some(UserAction::CycleSort),
        KeyCode::Char('v') => Some(UserAction::CycleSeverityFilter),
        KeyCode::Char('r') => Some(UserAction::ToggleReview),
        KeyCode::Char('n') => Some(UserAction::OpenLauncher),
        KeyCode::Char('w') => Some(UserAction::SaveCurrentReport),
        KeyCode::Char('t') => Some(UserAction::CycleTheme),
        KeyCode::Char('a') => Some(UserAction::ToggleAscii),
        KeyCode::Char('?') => Some(UserAction::ToggleHelp),
        KeyCode::Char('c') => Some(UserAction::CancelRun),
        KeyCode::Char('q') => Some(UserAction::Quit),
        _ => None,
    }
}
