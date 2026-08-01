use url::{Host, Url};

pub(crate) fn validated_issuer(value: &str) -> Result<Url, String> {
    let mut issuer = Url::parse(value).map_err(|error| format!("issuer URL 无效: {error}"))?;
    if !matches!(issuer.scheme(), "http" | "https")
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err("issuer URL 必须是无用户信息、查询参数与片段的 HTTP(S) 绝对地址".to_owned());
    }
    if issuer.scheme() == "http" && !issuer_uses_loopback(&issuer) {
        return Err("issuer URL 必须使用 HTTPS；仅 localhost 或回环 IP 可使用 HTTP".to_owned());
    }
    if !issuer.path().ends_with('/') {
        issuer.set_path(&format!("{}/", issuer.path()));
    }
    Ok(issuer)
}

pub(crate) fn issuer_uses_loopback(issuer: &Url) -> bool {
    match issuer.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::validated_issuer;

    #[test]
    fn issuer_rejects_query_parameters_that_endpoint_join_would_discard() {
        assert!(
            validated_issuer("https://auth.example.com/tenant?tenant=x").is_err(),
            "issuer 查询参数不得在端点拼接时被静默丢弃",
        );
    }
}
