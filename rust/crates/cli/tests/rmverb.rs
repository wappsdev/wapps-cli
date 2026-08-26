// `secrets rm` ve `projects rm` — bu dilimin SILEN fiilleri.
//
// Onay sozlesmesi bir ayrinti degil, bu iki fiilin varlik sebebi: silme GERI
// ALINAMAZ. Belirsizlik iptal demektir, o yuzden kabul edilen TEK cevap tam
// olarak "yes"; "y" da, "YES" de, bos girdi de REDDEDILIR. Bir "kolaylik"
// olarak "y"yi kabul etmek, yanlis pencerede Enter'a basan operatoru bir
// sirdan eder.
//
// Ajan-modu kapilari ayrica tests/verbpolicy.rs'te pinli: `rm` REFUSE_AGENT,
// `projects rm` CONTROL.
use wapps::confirm;
use wapps::projectsverb;
use wapps::rmverb;

// --- onay: YALNIZCA "yes" ---------------------------------------------------

#[test]
fn only_the_exact_word_yes_confirms() {
    for answer in ["yes\n", "yes", "  yes  \n", "yes\r\n"] {
        let mut out: Vec<u8> = Vec::new();
        assert!(
            confirm::ask(&mut answer.as_bytes(), &mut out, "prompt: "),
            "{answer:?} onay SAYILMALI"
        );
    }
}

#[test]
fn anything_other_than_yes_aborts() {
    // "y" ve "YES" BILINCLI olarak burada: ikisi de reddediliyor. Silme geri
    // alinamaz, o yuzden kisaltma ve buyuk/kucuk harf toleransi YOK.
    for answer in ["", "no\n", "y\n", "YES\n", "Yes\n", "yes please\n", "\n"] {
        let mut out: Vec<u8> = Vec::new();
        assert!(
            !confirm::ask(&mut answer.as_bytes(), &mut out, "prompt: "),
            "{answer:?} onay SAYILMAMALI"
        );
    }
}

#[test]
fn the_prompt_is_written_before_the_answer_is_read() {
    let mut out: Vec<u8> = Vec::new();
    confirm::ask(&mut "no\n".as_bytes(), &mut out, "Remove X? ");
    assert_eq!(String::from_utf8(out).unwrap(), "Remove X? ");
}

// --- rm: onay istemi ve basari satiri ---------------------------------------

#[test]
fn the_rm_prompt_names_both_the_key_and_the_project() {
    assert_eq!(
        rmverb::prompt("NVL_ZITADEL_PAT", "navlun-app"),
        "Remove NVL_ZITADEL_PAT from navlun-app? This cannot be undone. \
         Type 'yes' to confirm: "
    );
}

#[test]
fn the_rm_success_line_names_the_key_and_never_a_value() {
    let line = rmverb::success_line("STALE_KEY", "testproj");
    assert_eq!(line, "✓ Removed STALE_KEY (store: testproj)\n");
}

// --- projects rm ------------------------------------------------------------

#[test]
fn the_project_rm_prompt_names_the_project() {
    assert_eq!(
        projectsverb::rm_prompt("navlun-app"),
        "Remove project navlun-app and ALL of its keys? This cannot be undone. \
         Type 'yes' to confirm: "
    );
}

// Pointer-event izi TUTULUR ve bu ciktida ADIYLA soylenir: o iz, projenin var
// oldugunun tamper-evident kaydi ve silinmesi temiz bir gecmis UYDURMAK olurdu.
#[test]
fn the_project_rm_success_line_reports_the_kept_pointer_trail() {
    assert_eq!(
        projectsverb::rm_success_line("vaulter", 17, true),
        "✓ Removed project vaulter (17 objects)\n  \
         pointer-event trail kept (append-only DR record)\n"
    );
}

#[test]
fn the_project_rm_success_line_omits_the_trail_note_when_not_kept() {
    assert_eq!(
        projectsverb::rm_success_line("vaulter", 0, false),
        "✓ Removed project vaulter (0 objects)\n"
    );
}
