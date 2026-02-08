use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    text::{Line, Span},
    Frame,
};
use crate::ui::app::AppState;
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header Stats
            Constraint::Min(0),     // Logs / Status
        ])
        .split(area);

    draw_header_stats(f, app, chunks[0]);
    draw_system_logs(f, app, chunks[1]);
}

fn draw_header_stats(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);
        
    let style = Style::default().fg(IsotopeTheme::ACCENT);
    
    // Cipher
    let cipher = Paragraph::new(app.encryption_level.as_str())
        .block(Block::default().borders(Borders::ALL).title(" CIPHER "))
        .style(if app.encryption_level == "POST-QUANTUM" { Style::default().fg(IsotopeTheme::SUCCESS) } else { style });
    f.render_widget(cipher, chunks[0]);
    
    // Identity
    let identity = Paragraph::new(format!("{} @ {}", app.username, &app.identity_fp[..8]))
        .block(Block::default().borders(Borders::ALL).title(" IDENTITY "))
        .style(Style::default().fg(IsotopeTheme::THIS_USER));
    f.render_widget(identity, chunks[1]);
    
    // Uptime
    let uptime = Paragraph::new(format!("{}s", app.dashboard_state.uptime_secs))
        .block(Block::default().borders(Borders::ALL).title(" UPTIME "))
        .style(style);
    f.render_widget(uptime, chunks[2]);
    
    // RAM
    let ram = Paragraph::new(format!("{} MB", app.dashboard_state.ram_usage))
        .block(Block::default().borders(Borders::ALL).title(" RAM "))
        .style(style);
    f.render_widget(ram, chunks[3]);
}



fn draw_system_logs(f: &mut Frame, app: &AppState, area: Rect) {
    let logs: Vec<Line> = app.system_logs.iter()
        .rev()
        .take(10)
        .map(|m| {
             Line::from(vec![
                 Span::styled(format!("[{}] ", m.timestamp.format("%H:%M:%S")), Style::default().fg(Color::DarkGray)),
                 Span::styled(&m.content, Style::default().fg(IsotopeTheme::TEXT_PRIMARY)),
             ])
        })
        .collect();
        
    let para = Paragraph::new(logs)
        .block(Block::default().borders(Borders::ALL).title(" SYSTEM EVENT LOG "))
        .wrap(ratatui::widgets::Wrap { trim: true });
        
    f.render_widget(para, area);
}
