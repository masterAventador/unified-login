use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::issuer::validated_issuer;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("操作系统凭据库不可用: {0}")]
    Unavailable(String),
    #[error("凭据作用域配置无效: {0}")]
    InvalidConfiguration(String),
    #[error("拒绝保存空 refresh token")]
    EmptyToken,
}

pub trait CredentialStore: Send + Sync {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError>;
    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError>;
    fn delete_refresh_token(&self) -> Result<(), CredentialError>;

    /// 仅当当前凭据仍与预期值一致时删除，并且必须与同一凭据作用域的保存操作原子串行。
    fn delete_refresh_token_if_matches(
        &self,
        expected_refresh_token: &str,
    ) -> Result<bool, CredentialError>;
}

pub enum CredentialRestore {
    Available(String),
    LoginRequired,
}

pub fn restore_for_startup(store: &dyn CredentialStore) -> CredentialRestore {
    match store.load_refresh_token() {
        Ok(Some(refresh_token)) if !refresh_token.is_empty() => {
            CredentialRestore::Available(refresh_token)
        }
        Ok(_) | Err(_) => CredentialRestore::LoginRequired,
    }
}

pub fn scoped_credential_account(
    base_account: &str,
    issuer: &str,
    client_id: &str,
) -> Result<String, CredentialError> {
    let canonical_issuer =
        validated_issuer(issuer).map_err(CredentialError::InvalidConfiguration)?;
    let mut digest = Sha256::new();
    digest.update(canonical_issuer.as_str().as_bytes());
    digest.update([0]);
    digest.update(client_id.as_bytes());
    Ok(format!(
        "{base_account}:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
}

trait CredentialEntry: Send + Sync {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError>;
    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError>;
    fn delete_refresh_token(&self) -> Result<(), CredentialError>;
}

struct KeyringCredentialEntry {
    entry: keyring::Entry,
}

impl CredentialEntry for KeyringCredentialEntry {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
        normalize_read(self.entry.get_password())
    }

    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
        self.entry.set_password(refresh_token).map_err(unavailable)
    }

    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        normalize_delete(self.entry.delete_credential())
    }
}

struct SerializedCredentialEntry<E> {
    entry: E,
    operation_gate: Arc<Mutex<()>>,
}

impl<E: CredentialEntry> SerializedCredentialEntry<E> {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
        self.with_operation_gate(CredentialEntry::load_refresh_token)
    }

    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
        if refresh_token.is_empty() {
            return Err(CredentialError::EmptyToken);
        }
        self.with_operation_gate(|entry| entry.save_refresh_token(refresh_token))
    }

    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        self.with_operation_gate(CredentialEntry::delete_refresh_token)
    }

    fn delete_refresh_token_if_matches(
        &self,
        expected_refresh_token: &str,
    ) -> Result<bool, CredentialError> {
        self.with_operation_gate(|entry| {
            if entry.load_refresh_token()?.as_deref() != Some(expected_refresh_token) {
                return Ok(false);
            }
            entry.delete_refresh_token()?;
            Ok(true)
        })
    }

    fn with_operation_gate<T>(
        &self,
        action: impl FnOnce(&E) -> Result<T, CredentialError>,
    ) -> Result<T, CredentialError> {
        let _guard = self
            .operation_gate
            .lock()
            .map_err(|_| CredentialError::Unavailable("同一凭据账号的操作锁已经失效".to_owned()))?;
        action(&self.entry)
    }
}

/// 操作系统凭据库实现。
///
/// 同一进程内相同 service/account 的所有实例共享操作锁。操作系统凭据库不提供跨进程
/// compare-and-delete，因此宿主桌面应用还必须强制单实例；示例应用通过
/// `tauri-plugin-single-instance` 在创建认证状态前执行该约束。
pub struct SystemCredentialStore {
    inner: SerializedCredentialEntry<KeyringCredentialEntry>,
}

impl SystemCredentialStore {
    pub fn new(service: &str, account: &str) -> Result<Self, CredentialError> {
        let entry = keyring::Entry::new(service, account).map_err(unavailable)?;
        let operation_gate = shared_credential_operation_gate(service, account)?;
        Ok(Self {
            inner: SerializedCredentialEntry {
                entry: KeyringCredentialEntry { entry },
                operation_gate,
            },
        })
    }
}

impl CredentialStore for SystemCredentialStore {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
        self.inner.load_refresh_token()
    }

    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
        self.inner.save_refresh_token(refresh_token)
    }

    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        self.inner.delete_refresh_token()
    }

    fn delete_refresh_token_if_matches(
        &self,
        expected_refresh_token: &str,
    ) -> Result<bool, CredentialError> {
        self.inner
            .delete_refresh_token_if_matches(expected_refresh_token)
    }
}

type CredentialScope = (String, String);
type CredentialOperationGate = Mutex<()>;
type CredentialOperationGates = HashMap<CredentialScope, Weak<CredentialOperationGate>>;

fn shared_credential_operation_gate(
    service: &str,
    account: &str,
) -> Result<Arc<CredentialOperationGate>, CredentialError> {
    static OPERATION_GATES: OnceLock<Mutex<CredentialOperationGates>> = OnceLock::new();
    let mut gates = OPERATION_GATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| CredentialError::Unavailable("凭据操作锁注册表已经失效".to_owned()))?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    let scope = (service.to_owned(), account.to_owned());
    if let Some(gate) = gates.get(&scope).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(scope, Arc::downgrade(&gate));
    Ok(gate)
}

fn normalize_read(result: keyring::Result<String>) -> Result<Option<String>, CredentialError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(unavailable(error)),
    }
}

fn normalize_delete(result: keyring::Result<()>) -> Result<(), CredentialError> {
    match result {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(unavailable(error)),
    }
}

fn unavailable(error: keyring::Error) -> CredentialError {
    CredentialError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialEntry, CredentialError, CredentialRestore, CredentialStore,
        SerializedCredentialEntry, normalize_delete, normalize_read, restore_for_startup,
        scoped_credential_account, shared_credential_operation_gate,
    };
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn startup_restores_an_available_refresh_token() {
        let store = FakeStore::with_value("refresh-secret");

        let CredentialRestore::Available(token) = restore_for_startup(&store) else {
            panic!("存在 refresh token 时应恢复登录");
        };
        assert_eq!(token, "refresh-secret");
    }

    #[test]
    fn missing_or_denied_credentials_degrade_to_login_required_without_panicking() {
        let missing = FakeStore::default();
        assert!(matches!(
            restore_for_startup(&missing),
            CredentialRestore::LoginRequired
        ));

        let denied = FakeStore::denied();
        assert!(matches!(
            restore_for_startup(&denied),
            CredentialRestore::LoginRequired
        ));
    }

    #[test]
    fn save_and_logout_delete_the_only_secret() {
        let store = FakeStore::default();
        store
            .save_refresh_token("refresh-secret")
            .expect("凭据应可保存");
        assert_eq!(
            store.load_refresh_token().expect("凭据应可读取").as_deref(),
            Some("refresh-secret")
        );

        store.delete_refresh_token().expect("登出应可删除凭据");
        assert_eq!(store.load_refresh_token().expect("删除后仍应可读取"), None);
        store
            .delete_refresh_token()
            .expect("重复登出时删除不存在的条目也应成功");
    }

    #[test]
    fn stale_refresh_failure_cannot_delete_a_newer_rotated_credential() {
        let store = FakeStore::with_value("refresh-two");

        assert!(
            !store
                .delete_refresh_token_if_matches("refresh-one")
                .expect("旧凭据的条件删除应可判断"),
        );
        assert_eq!(
            store.load_refresh_token().expect("新凭据应仍可读取"),
            Some("refresh-two".to_owned()),
        );
        assert!(
            store
                .delete_refresh_token_if_matches("refresh-two")
                .expect("当前凭据应可条件删除"),
        );
        assert_eq!(store.load_refresh_token().expect("删除后应可读取"), None);
    }

    #[test]
    fn conditional_delete_is_atomic_with_a_concurrent_rotation() {
        let (read_started, read_started_receiver) = mpsc::channel();
        let (continue_delete, continue_delete_receiver) = mpsc::channel();
        let entry = Arc::new(RacingEntry {
            value: Mutex::new(Some("refresh-one".to_owned())),
            read_started: Mutex::new(Some(read_started)),
            continue_delete: Mutex::new(Some(continue_delete_receiver)),
        });
        let operation_gate = Arc::new(Mutex::new(()));
        let deleting_store = SerializedCredentialEntry {
            entry: Arc::clone(&entry),
            operation_gate: Arc::clone(&operation_gate),
        };
        let deletion = thread::spawn(move || {
            deleting_store
                .delete_refresh_token_if_matches("refresh-one")
                .expect("旧凭据的条件删除应完成")
        });

        read_started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("条件删除应先读到旧凭据");
        let saving_store = SerializedCredentialEntry {
            entry: Arc::clone(&entry),
            operation_gate,
        };
        let (save_completed, save_completed_receiver) = mpsc::channel();
        let saving = thread::spawn(move || {
            saving_store
                .save_refresh_token("refresh-two")
                .expect("轮换后的凭据应可保存");
            save_completed.send(()).expect("保存完成结果应可发送");
        });
        let save_completed_before_delete = save_completed_receiver
            .recv_timeout(Duration::from_millis(100))
            .is_ok();

        continue_delete.send(()).expect("条件删除应可继续");
        let deleted = deletion.join().expect("条件删除线程不应 panic");
        if !save_completed_before_delete {
            save_completed_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("条件删除完成后轮换保存应继续");
        }
        saving.join().expect("轮换保存线程不应 panic");

        assert!(
            !save_completed_before_delete,
            "条件检查到删除的整个区间必须阻止同一凭据账号被并发写入",
        );
        assert!(deleted, "匹配的旧凭据应被删除");
        assert_eq!(
            entry.load_refresh_token().expect("轮换凭据应仍可读取"),
            Some("refresh-two".to_owned()),
            "旧刷新失败绝不能删除并发写入的新轮换凭据",
        );
    }

    #[test]
    fn missing_system_keyring_entry_is_not_treated_as_an_infrastructure_failure() {
        assert_eq!(normalize_read(Err(keyring::Error::NoEntry)), Ok(None));
        assert_eq!(normalize_delete(Err(keyring::Error::NoEntry)), Ok(()));
    }

    #[test]
    fn credential_account_is_bound_to_the_canonical_issuer_and_client() {
        let canonical =
            scoped_credential_account("refresh-token", "http://localhost:9000", "demo-desktop")
                .expect("本地 issuer 应合法");
        let equivalent =
            scoped_credential_account("refresh-token", "http://localhost:9000/", "demo-desktop")
                .expect("带尾斜杠的同一 issuer 应合法");
        let other_issuer =
            scoped_credential_account("refresh-token", "http://localhost:9001", "demo-desktop")
                .expect("另一合法 issuer 应可生成隔离账号");
        let other_client =
            scoped_credential_account("refresh-token", "http://localhost:9000", "another-client")
                .expect("另一客户端应可生成隔离账号");

        assert_eq!(
            canonical,
            "refresh-token:WIQfe4OExQeL_wrKK52Bq0zoALxUBWsX0qYCKjX5gJY"
        );
        assert_eq!(canonical, equivalent);
        assert_ne!(canonical, other_issuer);
        assert_ne!(canonical, other_client);
        assert!(!canonical.contains("localhost"));
    }

    #[test]
    fn same_credential_scope_reuses_one_process_operation_gate() {
        let first = shared_credential_operation_gate("test-service", "test-account")
            .expect("相同作用域应可取得操作锁");
        let same = shared_credential_operation_gate("test-service", "test-account")
            .expect("相同作用域应可再次取得操作锁");
        let other = shared_credential_operation_gate("test-service", "other-account")
            .expect("不同作用域应可取得操作锁");

        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[derive(Default)]
    struct FakeStore {
        value: Mutex<Option<String>>,
        denied: bool,
    }

    impl FakeStore {
        fn with_value(value: &str) -> Self {
            Self {
                value: Mutex::new(Some(value.to_owned())),
                denied: false,
            }
        }

        fn denied() -> Self {
            Self {
                value: Mutex::new(None),
                denied: true,
            }
        }
    }

    impl CredentialStore for FakeStore {
        fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
            if self.denied {
                return Err(CredentialError::Unavailable("用户拒绝访问".to_owned()));
            }
            Ok(self.value.lock().expect("测试锁不应中毒").clone())
        }

        fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
            if refresh_token.is_empty() {
                return Err(CredentialError::EmptyToken);
            }
            *self.value.lock().expect("测试锁不应中毒") = Some(refresh_token.to_owned());
            Ok(())
        }

        fn delete_refresh_token(&self) -> Result<(), CredentialError> {
            *self.value.lock().expect("测试锁不应中毒") = None;
            Ok(())
        }

        fn delete_refresh_token_if_matches(
            &self,
            expected_refresh_token: &str,
        ) -> Result<bool, CredentialError> {
            let mut value = self.value.lock().expect("测试锁不应中毒");
            if value.as_deref() != Some(expected_refresh_token) {
                return Ok(false);
            }
            *value = None;
            Ok(true)
        }
    }

    struct RacingEntry {
        value: Mutex<Option<String>>,
        read_started: Mutex<Option<mpsc::Sender<()>>>,
        continue_delete: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl RacingEntry {
        fn load_unlocked(&self) -> Option<String> {
            let value = self.value.lock().expect("测试值锁不应中毒").clone();
            if let Some(read_started) = self.read_started.lock().expect("测试通知锁不应中毒").take()
            {
                read_started.send(()).expect("读取通知应可发送");
                self.continue_delete
                    .lock()
                    .expect("测试继续锁不应中毒")
                    .take()
                    .expect("条件删除应有继续信号")
                    .recv()
                    .expect("条件删除继续信号应可接收");
            }
            value
        }
    }

    impl CredentialEntry for Arc<RacingEntry> {
        fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
            Ok(self.load_unlocked())
        }

        fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
            *self.value.lock().expect("测试值锁不应中毒") = Some(refresh_token.to_owned());
            Ok(())
        }

        fn delete_refresh_token(&self) -> Result<(), CredentialError> {
            *self.value.lock().expect("测试值锁不应中毒") = None;
            Ok(())
        }
    }
}
