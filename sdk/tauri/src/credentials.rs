#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("操作系统凭据库不可用: {0}")]
    Unavailable(String),
    #[error("拒绝保存空 refresh token")]
    EmptyToken,
}

pub trait CredentialStore: Send + Sync {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError>;
    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError>;
    fn delete_refresh_token(&self) -> Result<(), CredentialError>;
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

pub struct SystemCredentialStore {
    entry: keyring::Entry,
}

impl SystemCredentialStore {
    pub fn new(service: &str, account: &str) -> Result<Self, CredentialError> {
        let entry = keyring::Entry::new(service, account).map_err(unavailable)?;
        Ok(Self { entry })
    }
}

impl CredentialStore for SystemCredentialStore {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
        normalize_read(self.entry.get_password())
    }

    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
        if refresh_token.is_empty() {
            return Err(CredentialError::EmptyToken);
        }
        self.entry.set_password(refresh_token).map_err(unavailable)
    }

    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        normalize_delete(self.entry.delete_credential())
    }
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
        CredentialError, CredentialRestore, CredentialStore, normalize_delete, normalize_read,
        restore_for_startup,
    };
    use std::sync::Mutex;

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
    fn missing_system_keyring_entry_is_not_treated_as_an_infrastructure_failure() {
        assert_eq!(normalize_read(Err(keyring::Error::NoEntry)), Ok(None));
        assert_eq!(normalize_delete(Err(keyring::Error::NoEntry)), Ok(()));
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
    }
}
