use tauri::plugin::TauriPlugin;
use tauri::test::MockRuntime;
use unified_login_tauri::auth::AuthConfig;
use unified_login_tauri::plugin::{Builder, PLUGIN_INVOKE_PREFIX, PLUGIN_NAME};

#[test]
fn standard_tauri_plugin_exposes_a_stable_namespace_and_builder() {
    let config = AuthConfig::builder(
        "https://login.example.com",
        "desktop-client",
        "com.example.desktop",
    )
    .build()
    .expect("测试配置应有效");

    let _plugin: TauriPlugin<MockRuntime> = Builder::new(config).build();

    assert_eq!(PLUGIN_NAME, "unified-login-tauri");
    assert_eq!(
        PLUGIN_INVOKE_PREFIX, "plugin:unified-login-tauri|",
        "TypeScript 与 Rust 必须共享稳定的插件命令命名空间",
    );
}

#[test]
fn plugin_can_manage_invalid_runtime_configuration_without_panicking() {
    let invalid_config = AuthConfig::builder(
        "not a valid issuer",
        "desktop-client",
        "com.example.desktop",
    )
    .build();

    let _plugin: TauriPlugin<MockRuntime> = Builder::from_config_result(invalid_config).build();
}

#[test]
fn public_plugin_type_does_not_pin_a_single_tauri_patch_release() {
    let manifest = include_str!("../Cargo.toml");

    assert!(
        manifest.contains("tauri = { version = \"2.11\", default-features = false }"),
        "公开返回 TauriPlugin 的依赖必须允许与宿主应用统一到兼容的 Tauri v2 版本",
    );
    assert!(!manifest.contains("tauri = { version = \"=2.11.5\""));
}

#[test]
fn browser_opening_does_not_pin_the_hosts_opener_plugin() {
    let manifest = include_str!("../Cargo.toml");
    let plugin_source = include_str!("../src/plugin.rs");

    assert!(
        manifest.contains("open = { version = \"5\", features = [\"shellexecute-on-windows\"] }")
    );
    assert!(!manifest.contains("tauri-plugin-opener"));
    assert!(!plugin_source.contains("tauri_plugin_opener"));
}
