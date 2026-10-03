// agentmode, ajan/CI baglamini saptar ve gizli-deger basan her verb yuzeyini
// yapisal olarak reddeder.
//
// Ajan modu DEFAULT-ON: herhangi bir ajan/CI ortam isareti VARSA veya stdin bir
// TTY DEGILSE. Bu, portun pty ile olculmesinin somut sebebi: boru ile kosan bir
// olcum stdin'i non-TTY yapar, yani DAIMA ajan modu olcer ve insan yolunu hic
// gormez.
use crate::clierr::{Code, Error};

// agent_env_markers, varligi ajan/CI baglami isaret eden ortam degiskenleridir.
const AGENT_ENV_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE",
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "WOODPECKER",
    "CI_PIPELINE_ID",
    "BUILDKITE",
    "GITLAB_CI",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "TF_BUILD",
];

/// Detector, saptamanin test-edilebilir bicimidir.
pub struct Detector<'a> {
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub stdin_is_tty: bool,
    /// allow_override true ise WAPPS_AGENT_MODE=0 YALNIZCA stdin TTY iken
    /// onurlandirilir — bir ajan kendini insan moduna ceviremez (yapisal).
    pub allow_override: bool,
}

impl Detector<'_> {
    pub fn is_agent(&self) -> bool {
        if self.allow_override
            && self.stdin_is_tty
            && (self.env)("WAPPS_AGENT_MODE").as_deref() == Some("0")
        {
            return false;
        }
        if !self.stdin_is_tty {
            return true;
        }
        AGENT_ENV_MARKERS
            .iter()
            .any(|k| (self.env)(k).is_some_and(|v| !v.is_empty()))
    }
}

fn real_env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// stdin_is_tty, uretim TTY saptamasidir.
pub fn stdin_is_tty() -> bool {
    rustix::termios::isatty(std::io::stdin())
}

/// is_agent, uretim saptayicisini kullanir.
pub fn is_agent() -> bool {
    Detector {
        env: &real_env,
        stdin_is_tty: stdin_is_tty(),
        allow_override: true,
    }
    .is_agent()
}

/// Politika adlari (Go tarafiyla ayni dizeler).
pub const POLICY_ALLOW: &str = "allow";
pub const POLICY_CONTROL: &str = "control";
pub const POLICY_TTY: &str = "tty";
pub const POLICY_REFUSE_AGENT: &str = "refuse_agent";

/// guard, verilen politikayi ajan moduna karsi uygular. Bilinmeyen/bos politika
/// FAIL-CLOSED: MERKEZI TABLOYA (agentgate.go'daki agentPolicy, Rust'ta
/// verb_policy) eklenmesi unutulmus yeni bir verb REFUSED'a duser.
///
/// "annotation" DEMIYOR, ve bu duzeltilmis bir yanlis: politika bir cobra
/// annotation'indan HIC gelmiyordu. `wapps_agent_policy` annotation'inin
/// uretim kodunda SIFIR okuyucusu vardi ve mekanizma tumuyle olu oldugu icin
/// silindi. Yetkiyi veren sey TABLO.
pub fn guard(policy: &str, is_agent: bool) -> Result<(), Error> {
    if !is_agent {
        return Ok(());
    }
    match policy {
        POLICY_ALLOW => Ok(()),
        POLICY_CONTROL => Err(Error::new(
            Code::ControlPlaneRequired,
            "control-plane operation refused in agent mode",
        )),
        POLICY_TTY => Err(Error::new(
            Code::AgentModeRefused,
            "this command requires a human terminal",
        )),
        _ => Err(Error::new(
            Code::AgentModeRefused,
            "surface refused in agent mode (prints secret values or is irreversible)",
        )),
    }
}
