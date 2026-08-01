use tauri::Manager;
use unified_login_tauri::auth::{AuthConfig, AuthError};
use unified_login_tauri::plugin::Builder as AuthPluginBuilder;

const CLIENT_ID: &str = "demo-desktop";
const CREDENTIAL_SERVICE: &str = "com.aventador.unified-login.demo-desktop";
const CREDENTIAL_ACCOUNT: &str = "refresh-token";
const CREDENTIAL_SERVICE_ENV: &str = "UNIFIED_LOGIN_CREDENTIAL_SERVICE";
const DEFAULT_ISSUER: &str = "http://localhost:9000";
const WINDOW_STARTUP_MODE_ENV: &str = "UNIFIED_LOGIN_WINDOW_STARTUP_MODE";

#[derive(Clone, Copy, Debug, PartialEq)]
enum WindowStartupMode {
    Default,
    Hidden,
}

impl WindowStartupMode {
    fn should_show_window(&self) -> bool {
        *self == Self::Default
    }

    fn should_focus_after_login(&self) -> bool {
        *self == Self::Default
    }
}

fn window_startup_mode(value: Option<&str>) -> WindowStartupMode {
    match value {
        Some("hidden") => WindowStartupMode::Hidden,
        _ => WindowStartupMode::Default,
    }
}

fn current_window_startup_mode() -> WindowStartupMode {
    window_startup_mode(std::env::var(WINDOW_STARTUP_MODE_ENV).ok().as_deref())
}

trait ExistingInstanceTarget {
    fn focus(&self);
    fn show(&self);
}

impl<R: tauri::Runtime> ExistingInstanceTarget for tauri::WebviewWindow<R> {
    fn focus(&self) {
        let _ = self.set_focus();
    }

    fn show(&self) {
        let _ = self.show();
    }
}

fn activate_existing_instance<T: ExistingInstanceTarget>(
    target: &T,
    startup_mode: &WindowStartupMode,
) {
    if startup_mode.should_show_window() {
        target.show();
        target.focus();
    }
}

#[cfg(any(target_os = "macos", test))]
trait ActivationPolicyTarget {
    fn suppress_activation(&mut self);
}

#[cfg(target_os = "macos")]
impl<R: tauri::Runtime> ActivationPolicyTarget for tauri::App<R> {
    fn suppress_activation(&mut self) {
        self.set_activation_policy(tauri::ActivationPolicy::Prohibited);
    }
}

#[cfg(any(target_os = "macos", test))]
fn configure_macos_activation<T: ActivationPolicyTarget>(
    mut target: T,
    startup_mode: &WindowStartupMode,
) -> T {
    if *startup_mode == WindowStartupMode::Hidden {
        target.suppress_activation();
    }
    target
}

fn credential_service(value: Option<&str>) -> &str {
    value
        .filter(|candidate| !candidate.is_empty())
        .unwrap_or(CREDENTIAL_SERVICE)
}

fn desktop_auth_config(issuer: &str, credential_service: &str) -> Result<AuthConfig, AuthError> {
    AuthConfig::builder(issuer, CLIENT_ID, credential_service)
        .credential_account(CREDENTIAL_ACCOUNT)
        .build()
}

fn current_auth_config() -> Result<AuthConfig, AuthError> {
    let issuer =
        std::env::var("UNIFIED_LOGIN_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_owned());
    let credential_service_override = std::env::var(CREDENTIAL_SERVICE_ENV).ok();
    desktop_auth_config(
        &issuer,
        credential_service(credential_service_override.as_deref()),
    )
}

pub fn run() {
    let startup_mode = current_window_startup_mode();
    let setup_mode = startup_mode;
    let auth_plugin = AuthPluginBuilder::from_config_result(current_auth_config())
        .on_login_success(|app| {
            // 认证令牌已经成功保存后，窗口聚焦只能算尽力而为；纯 UI 原因不能把成功登录
            // 错误地报告成失败。窗口标签和启动模式仍完全属于应用自身。
            if current_window_startup_mode().should_focus_after_login()
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.set_focus();
            }
        })
        .build();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                activate_existing_instance(&window, &current_window_startup_mode());
            }
        }))
        .plugin(auth_plugin)
        .setup(move |app| {
            let window = app
                .get_webview_window("main")
                .ok_or("找不到桌面应用主窗口")?;
            if setup_mode.should_show_window() {
                window.show()?;
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Tauri 桌面应用构建失败");
    #[cfg(target_os = "macos")]
    let app = configure_macos_activation(app, &startup_mode);
    app.run(|_, _| {});
}

#[cfg(test)]
mod tests {
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{INVOKE_KEY, get_ipc_response, mock_builder};
    use tauri::webview::InvokeRequest;
    use unified_login_tauri::auth::AuthConfig;
    use unified_login_tauri::plugin::Builder as AuthPluginBuilder;

    use super::{
        ActivationPolicyTarget, CREDENTIAL_SERVICE, DEFAULT_ISSUER, ExistingInstanceTarget,
        WindowStartupMode, activate_existing_instance, configure_macos_activation,
        credential_service, desktop_auth_config, window_startup_mode,
    };

    #[test]
    fn automation_window_mode_is_hidden_without_changing_the_default() {
        assert_eq!(window_startup_mode(None), WindowStartupMode::Default);
        assert_eq!(
            window_startup_mode(Some("hidden")),
            WindowStartupMode::Hidden
        );
        assert_eq!(
            window_startup_mode(Some("unexpected")),
            WindowStartupMode::Default
        );
        assert!(WindowStartupMode::Default.should_show_window());
        assert!(!WindowStartupMode::Hidden.should_show_window());
        assert!(WindowStartupMode::Default.should_focus_after_login());
        assert!(!WindowStartupMode::Hidden.should_focus_after_login());
    }

    #[test]
    fn activation_configuration_owns_and_returns_the_target_before_the_event_loop() {
        let hidden = configure_macos_activation(
            FakeActivationPolicyTarget::default(),
            &WindowStartupMode::Hidden,
        );
        assert_eq!(hidden.suppression_count, 1);

        let default = configure_macos_activation(
            FakeActivationPolicyTarget::default(),
            &WindowStartupMode::Default,
        );
        assert_eq!(default.suppression_count, 0);
    }

    #[test]
    fn second_instance_focuses_only_the_normal_visible_application() {
        let visible = FakeExistingInstanceTarget::default();
        activate_existing_instance(&visible, &WindowStartupMode::Default);
        assert_eq!(visible.show_count.get(), 1);
        assert_eq!(visible.focus_count.get(), 1);

        let hidden = FakeExistingInstanceTarget::default();
        activate_existing_instance(&hidden, &WindowStartupMode::Hidden);
        assert_eq!(hidden.show_count.get(), 0);
        assert_eq!(hidden.focus_count.get(), 0);
    }

    #[test]
    fn isolated_credential_service_does_not_change_the_production_default() {
        assert_eq!(credential_service(None), CREDENTIAL_SERVICE);
        assert_eq!(credential_service(Some("")), CREDENTIAL_SERVICE);
        assert_eq!(
            credential_service(Some("com.aventador.unified-login.acceptance.isolated")),
            "com.aventador.unified-login.acceptance.isolated"
        );
    }

    #[test]
    fn application_owns_only_its_authentication_configuration() {
        let config = desktop_auth_config(DEFAULT_ISSUER, CREDENTIAL_SERVICE)
            .expect("桌面示例认证配置应有效");

        assert_eq!(config.issuer(), "http://localhost:9000/");
        assert_eq!(config.client_id(), "demo-desktop");
        assert_eq!(config.credential_service(), CREDENTIAL_SERVICE);
        assert_eq!(config.scopes(), ["openid"]);
    }

    #[test]
    fn configured_capability_reaches_the_namespaced_sdk_command() {
        let invalid_config = AuthConfig::builder(
            "not a valid issuer",
            "desktop-client",
            "com.example.desktop",
        )
        .build();
        let app = mock_builder()
            .plugin(AuthPluginBuilder::from_config_result(invalid_config).build())
            .build(tauri::generate_context!("tauri.conf.json", test = true))
            .expect("应使用生产 capability 构建测试应用");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("应创建受 default capability 管理的主窗口");

        let response = get_ipc_response(
            &webview,
            InvokeRequest {
                cmd: "plugin:unified-login-tauri|get_access_token".into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: "tauri://localhost".parse().expect("测试 IPC URL 应有效"),
                body: InvokeBody::default(),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_owned(),
            },
        )
        .expect_err("无效配置应由 SDK 命令返回结构化错误");

        assert_eq!(
            response.get("code").and_then(|value| value.as_str()),
            Some("configuration"),
            "命令必须真实进入 SDK 插件，不能被 ACL 拒绝为 Plugin not found",
        );
    }

    #[derive(Default)]
    struct FakeActivationPolicyTarget {
        suppression_count: usize,
    }

    impl ActivationPolicyTarget for FakeActivationPolicyTarget {
        fn suppress_activation(&mut self) {
            self.suppression_count += 1;
        }
    }

    #[derive(Default)]
    struct FakeExistingInstanceTarget {
        focus_count: std::cell::Cell<usize>,
        show_count: std::cell::Cell<usize>,
    }

    impl ExistingInstanceTarget for FakeExistingInstanceTarget {
        fn focus(&self) {
            self.focus_count.set(self.focus_count.get() + 1);
        }

        fn show(&self) {
            self.show_count.set(self.show_count.get() + 1);
        }
    }
}
