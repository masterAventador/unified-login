#![cfg(target_os = "macos")]

use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use unified_login_tauri::credentials::{CredentialStore, SystemCredentialStore};

#[test]
#[ignore = "会在 macOS 钥匙串中创建并删除独立临时条目"]
fn macos_system_keychain_round_trip_is_headless_and_deletes_the_entry() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间必须晚于 Unix epoch")
        .as_nanos();
    let service = format!(
        "com.aventador.unified-login.acceptance.{}.{}",
        process::id(),
        suffix
    );
    let account = "refresh-token";
    let secret = format!("temporary-refresh-token-{suffix}");
    let store = SystemCredentialStore::new(&service, account)
        .expect("macOS 系统凭据库应能创建临时条目句柄");

    let verification = (|| -> Result<(), String> {
        store
            .save_refresh_token(&secret)
            .map_err(|error| format!("保存临时 refresh token 失败: {error}"))?;
        let loaded = store
            .load_refresh_token()
            .map_err(|error| format!("读取临时 refresh token 失败: {error}"))?;
        if loaded.as_deref() != Some(secret.as_str()) {
            return Err("从系统凭据库读回的 refresh token 不一致".to_owned());
        }
        store
            .delete_refresh_token()
            .map_err(|error| format!("删除临时 refresh token 失败: {error}"))?;
        if store
            .load_refresh_token()
            .map_err(|error| format!("删除后检查临时 refresh token 失败: {error}"))?
            .is_some()
        {
            return Err("删除后系统凭据库仍返回 refresh token".to_owned());
        }
        Ok(())
    })();

    let cleanup = store.delete_refresh_token();
    assert!(cleanup.is_ok(), "临时钥匙串条目兜底清理失败: {cleanup:?}");
    assert!(verification.is_ok(), "{verification:?}");
}
