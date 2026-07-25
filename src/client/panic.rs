use std::fs::{self, OpenOptions};
use std::io::{Write, Seek};
use std::path::{Path, PathBuf};
use rand::RngCore;

pub fn set_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture
        );
        original_hook(info);
    }));
}

pub fn nuke_everything(identity_path: &str) {
    fn secure_wipe(path: &Path) {
        if let Ok(metadata) = fs::metadata(path) {
            let len = metadata.len() as usize;
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                let chunk_size = 4096;
                let mut buf = vec![0u8; chunk_size];
                for _pass in 0..3 {
                    let _ = file.seek(std::io::SeekFrom::Start(0));
                    let mut written = 0;
                    while written < len {
                        rand::rngs::OsRng.fill_bytes(&mut buf);
                        let to_write = std::cmp::min(chunk_size, len - written);
                        let _ = file.write_all(&buf[..to_write]);
                        written += to_write;
                    }
                    let _ = file.sync_all();
                }
            }
            let _ = fs::remove_file(path);
        }
    }

    if Path::new(identity_path).exists() {
        secure_wipe(Path::new(identity_path));
    }

    let vault_path = Path::new("isotope.vault");
    if vault_path.exists() {
        secure_wipe(vault_path);
    }

    if let Ok(entries) = fs::read_dir("downloads") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                secure_wipe(&path);
            }
        }
        let _ = fs::remove_dir_all("downloads");
    }
}

pub fn expand_path(input: &str) -> PathBuf {
    let input = input.trim();
    if input.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            let without_tilde = input.trim_start_matches('~');
            let path_str = if without_tilde.starts_with('/') {
                format!("{}{}", home, without_tilde)
            } else {
                format!("{}/{}", home, without_tilde)
            };
            return PathBuf::from(path_str);
        }
    }
    PathBuf::from(input)
}
