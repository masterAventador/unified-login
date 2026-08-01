use tauri::plugin::TauriPlugin;
use unified_login_tauri::auth::AuthConfig;
use unified_login_tauri::plugin::Builder as AuthPluginBuilder;

pub fn auth_plugin<R: tauri::Runtime>(issuer: &str) -> TauriPlugin<R> {
    let config = AuthConfig::builder(
        issuer,
        "second-desktop-client",
        "com.example.second-desktop",
    )
    .scopes(["openid", "profile"])
    .build();

    AuthPluginBuilder::from_config_result(config).build()
}
