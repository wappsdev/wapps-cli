// session, gate koku + kimlik header'larini cozer.
use crate::clierr::{Code, Error};

/// DEFAULT_GATE_URL, varsayilan gate hostname'idir.
pub const DEFAULT_GATE_URL: &str = "https://gw.meapps.dev";

/// gate_url, WAPPS_SECRETS_GATE env'i ya da varsayilan.
pub fn gate_url() -> String {
    match std::env::var("WAPPS_SECRETS_GATE") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
        _ => DEFAULT_GATE_URL.to_string(),
    }
}

/// AuthHeader, bir isteğe eklenecek (ad, deger) ciftidir.
pub type AuthHeader = (String, String);

/// HeaderAccessToken, CF Access app-token header adidir.
pub const HEADER_ACCESS_TOKEN: &str = "cf-access-token";

/// auth_headers, kimlik header'larini uretir.
///
/// 1) CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET → service-token yolu.
/// 2) aksi halde WAPPS_SESSION_TOKEN → cf-access-token.
/// 3) hicbiri yoksa SESSION_EXPIRED — istek aga HIC cikmaz.
pub fn auth_headers() -> Result<Vec<AuthHeader>, Error> {
    let id = std::env::var("CF_ACCESS_CLIENT_ID").unwrap_or_default();
    let secret = std::env::var("CF_ACCESS_CLIENT_SECRET").unwrap_or_default();
    if !id.is_empty() && !secret.is_empty() {
        let mut h = vec![
            ("CF-Access-Client-Id".to_string(), id),
            ("CF-Access-Client-Secret".to_string(), secret),
        ];
        if let Ok(mt) = std::env::var("WAPPS_MACHINE_TOKEN") {
            if !mt.is_empty() {
                h.push(("Authorization".to_string(), format!("Bearer {mt}")));
            }
        }
        return Ok(h);
    }
    match std::env::var("WAPPS_SESSION_TOKEN") {
        Ok(t) if !t.is_empty() => Ok(vec![(HEADER_ACCESS_TOKEN.to_string(), t)]),
        _ => Err(Error::new(
            Code::SessionExpired,
            "no valid CF Access session for the secrets gate",
        )
        .with_recovery("run 'wapps login'")),
    }
}
