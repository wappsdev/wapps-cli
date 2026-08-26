// `secrets trust-repo`: baglamayi KURAN fiil.
//
// ORACLE: cmd/secrets/trustrepo.go (runTrustRepo, trustRepoCore, shortRepo).
// Metinler Go ikilisinden pty altinda OLCULDU, tahmin edilmedi.
//
// IKI INCELIK, ve ikisi de bu dosyada pinli:
//
//  1. ONAY KELIMESI FARKLI. Satir ici baglama istemi ("Bind them? [y/N]")
//     "y" VE "yes" kabul ediyor; trust-repo'nunki YALNIZCA "y"
//     (strings.EqualFold, yani "Y" da olur ama "yes" OLMAZ). Iki istemi tek
//     bir onay fonksiyonuna indirmek bu farki sessizce silerdi.
//  2. ISTEM STDOUT'A gidiyor (cmd.OutOrStdout()), satir ici baglama isteminin
//     aksine (o stderr'e). Differential stdout ve stderr'i AYRI pty'lerde
//     yakaladigi icin bu fark olculebilir.
use wapps::trustrepo;
use wapps::wappsyaml;

fn cfg(yaml: &str) -> wappsyaml::WappsYaml {
    wappsyaml::parse(yaml.as_bytes()).expect("gecerli config")
}

#[test]
fn the_prompt_block_names_repo_project_and_backend() {
    let c = cfg("version: 2\nproject: testproj\n");
    assert_eq!(
        trustrepo::prompt_block("/repo/path", &c),
        "Pin repo→project binding:\n  repo:    /repo/path\n  project: testproj\n  backend: store\nPin this binding? [y/N]: "
    );
}

#[test]
fn profiles_are_listed_sorted_when_present() {
    let c = cfg("version: 2\nproject: p\nprofiles:\n  web: [A]\n  api: [B]\n");
    assert!(
        trustrepo::prompt_block("r", &c).contains("\n  profiles: api, web\n"),
        "profiller alfabetik siralanmali: {}",
        trustrepo::prompt_block("r", &c)
    );
}

#[test]
fn an_empty_profile_map_prints_no_profiles_line() {
    let c = cfg("version: 2\nproject: p\n");
    assert!(!trustrepo::prompt_block("r", &c).contains("profiles"));
}

#[test]
fn short_repo_truncates_at_sixty_characters() {
    // Go: len > 60 ise "…" + son 59 karakter.
    let long = "x".repeat(61);
    let got = trustrepo::short_repo(&long);
    assert_eq!(got, format!("…{}", "x".repeat(59)));
    // TAM 60 kisaltilmaz.
    let exact = "y".repeat(60);
    assert_eq!(trustrepo::short_repo(&exact), exact);
}

#[test]
fn the_success_line_uses_the_shortened_repo() {
    assert_eq!(trustrepo::success_line("/short", "proj"), "pinned /short → proj\n");
}

#[test]
fn only_y_confirms_and_yes_does_not() {
    // Bu, satir ici baglama isteminden AYRILDIGI yer: orada "yes" gecerli.
    for (answer, want) in [
        ("y\n", true),
        ("Y\n", true),
        ("  y  \n", true),
        ("yes\n", false),
        ("n\n", false),
        ("\n", false),
        ("", false), // EOF
    ] {
        let mut r = answer.as_bytes();
        let mut w: Vec<u8> = Vec::new();
        assert_eq!(
            trustrepo::confirm_y(&mut r, &mut w, "p: "),
            want,
            "cevap {answer:?}"
        );
    }
}
