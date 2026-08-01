const COMMANDS: &[&str] = &["login", "get_access_token", "logout"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
