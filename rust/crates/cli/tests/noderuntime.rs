// NODE BU DEPODA HICBIR `.ts` DOSYASINI KOSMUYOR — ve bu bir gozlem degil, KAPI.
//
// # Olculen olgu (komsu depoda)
//
// wapps-platform'da Homebrew node'u v25.2.1'den v26.7.0'a tasidi, agacta tek
// satir degismedi, `cargo test --workspace` 0'dan 101'e dustu. Sebep: node'un
// VARSAYILAN kipi "yalnizca tip sok" ve o kip bazi TypeScript bicimlerini
// REDDEDIYOR — parametre ozelligi, enum, namespace, `export =`,
// `import x = require`. Ariza "dusen bir test" olarak degil, "baslayamayan bir
// surec" olarak geliyor: modul hic yuklenmiyor.
//
// # Bu deponun durumu — OLCULDU, 2026-08-28
//
//   - 46 izlenen `.ts` var (`worker/`), 45'i bildirim dosyasi degil.
//   - Bunlarin 11'i PARAMETRE OZELLIGI kullaniyor: audit-do, auth, crypto/blob,
//     crypto/kek, index, manifest, policy, scheduler-do, writer-do,
//     test/fetchmock, test/state-replication.
//   - Ve node bu dosyalarin HICBIRINI kosmuyor. `worker/`u ceviren sey vitest
//     (esbuild) ve `tsc`; ikisi de kendi donusumunu yapiyor, node'un sokucusunu
//     DEGIL. Go tarafi `exec.Command` ile git/cloudflared/tofu cagiriyor,
//     node'u degil.
//
// Yani o 11 dosya bugun bir ariza DEGIL. Onlari komsu deponun kisitina uydurmak
// icin yeniden yazmak, hicbir seyin uygulamadigi bir kural ugruna uretim kodunu
// degistirmek olurdu — bu estate'in vakum dedigi sey.
//
// # O halde bu kapi NEYI tutuyor
//
// TEK BIR SEYI: node'un buradaki bir `.ts`e hic dokunmadigi varsayimini.
// Varsayim dogru oldugu surece 11 dosya serbest. Yanlis oldugu GUN — biri bir
// oracle surucusu, bir preflight betigi ya da bir `node scripts/x.mjs` yazdigi
// gun — bu test kirmiziya doner ve borcu ADIYLA soyler. Cunku o gun, o 11 dosya
// sessizce "baslayamayan bir surec" haline gelir ve sebep TypeScript'te degil
// node'un surumunde aranir.
//
// Kapinin yuklemi SOZDIZIMSEL ve tarayicisinin kendi birim testleri var
// (asagida): "prose bir kenar degildir" dersi komsu depodan alindi — orada bir
// tarayicinin metin eslesmesine guvenmesi, kapiyi sessizce vakumlastirmisti.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

/// Bir kabuk komutu `node`u DOGRUDAN calistiriyor mu.
///
/// Zincirin her halkasina bakiyor (`&&`, `||`, `;`, `|`), cunku
/// `tsc --noEmit && node x.ts` ikinci halkada node kosuyor. Ilk SOZCUK
/// karsilastiriliyor: `npx`, `vitest`, `tsc` node'u kendileri calistirir ama
/// bir `.ts`i node'un SOKUCUSUNE vermezler — kendi donusumleri var, ve bu
/// ayrimin kaybi kapiyi her npm betiginde kirmiziya cevirirdi.
fn runs_node_directly(cmd: &str) -> bool {
    cmd.split([';', '|', '&'])
        .any(|halka| halka.split_whitespace().next() == Some("node"))
}

/// Bir kaynak satiri, `node` ADLI bir sureci baslatiyor mu.
///
/// Kapali bir bicim kumesi, ve kapali olmasi bu kapinin bilinen sinirlarindan
/// biri: listede olmayan bir bicimle (ornegin bir kabuk betigi icinden) node
/// cagirmak buradan kacar. Liste, iki depoda GERCEKTEN kullanilan surec baslatma
/// bicimlerinden turetildi.
fn names_node_as_a_process(line: &str) -> bool {
    let kod = line.split("//").next().unwrap_or(line);
    if kod.trim_start().starts_with('#') && !kod.trim_start().starts_with("#!") {
        return false;
    }
    const BICIMLER: [&str; 6] = [
        "Command::new(\"node\")",
        "exec.Command(\"node\"",
        "exec.CommandContext(ctx, \"node\"",
        "process.execPath",
        "Bun.spawn",
        "spawnSync(\"node\"",
    ];
    if BICIMLER.iter().any(|b| kod.contains(b)) {
        return true;
    }
    // Shebang: `#!/usr/bin/env node`
    kod.starts_with("#!") && kod.contains("node")
}

// --- tarayicinin KENDI kapisi ------------------------------------------------

#[test]
fn a_command_that_starts_with_node_is_seen() {
    assert!(runs_node_directly("node scripts/x.mjs"));
    assert!(runs_node_directly("node --test 'a/*.test.mjs'"));
}

#[test]
fn node_in_the_second_link_of_a_chain_is_seen() {
    // ILK halkaya bakan bir tarayici bunu kacirirdi.
    assert!(runs_node_directly("tsc --noEmit && node check.ts"));
    assert!(runs_node_directly("rm -rf dist; node build.mjs"));
}

#[test]
fn a_tool_that_merely_happens_to_be_written_in_node_is_not_seen() {
    // Bunlar node'u kosar ama `.ts`i KENDI donusumlerinden gecirir; node'un
    // sokucusune hicbir sey vermezler.
    assert!(!runs_node_directly("vitest run"));
    assert!(!runs_node_directly("tsc --noEmit"));
    assert!(!runs_node_directly("npx wrangler deploy"));
    assert!(!runs_node_directly("npm run typecheck"));
}

#[test]
fn a_word_that_merely_starts_with_node_is_not_the_binary() {
    assert!(!runs_node_directly("nodemon x.ts"));
    assert!(!runs_node_directly("./node_modules/.bin/vitest"));
}

#[test]
fn a_spawn_that_names_node_is_seen() {
    assert!(names_node_as_a_process(
        "    let out = Command::new(\"node\").arg(&d).output();"
    ));
    assert!(names_node_as_a_process(
        "\tcmd := exec.Command(\"node\", \"x.mjs\")"
    ));
    assert!(names_node_as_a_process(
        "  spawn(process.execPath, [script])"
    ));
    assert!(names_node_as_a_process("#!/usr/bin/env node"));
}

#[test]
fn prose_about_node_is_not_a_spawn() {
    // Komsu depodaki ders: adi anmak bir kenar degildir.
    assert!(!names_node_as_a_process("// node bu dosyayi asla kosmuyor"));
    assert!(!names_node_as_a_process(
        "\tcmd := exec.Command(\"git\", \"status\") // node degil"
    ));
    assert!(!names_node_as_a_process("# node:crypto ile uretildi"));
    assert!(!names_node_as_a_process("    let x = \"node_modules\";"));
}

// --- kapinin kendisi ---------------------------------------------------------

fn tracked_files(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files"])
        .output()
        .expect("git ls-files kosamadi");
    assert!(
        out.status.success(),
        "git ls-files basarisiz: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// TARAYICININ KENDI KAYNAGI — taramanin DISINDA, ve bu bir muafiyet degil bir
/// zorunluluk: yasakli bicimlerin listesi (`BICIMLER`) ve tarayicinin birim
/// testlerindeki fikstur satirlari BU DOSYADA duz metin olarak yaziyor. Yani
/// kapi, kendi SOZLUGUNU bir ihlal sayiyordu ve `git ls-files` altinda HER
/// KOSUMDA kirmizi doniyordu (bulgular: `:75 "process.execPath",`,
/// `:76 "Bun.spawn",`, `:121 assert!(names_node_as_a_process(...))`). Kirmizi
/// olan sey depo degil olcuyu tutan cetveldi.
///
/// BEDELI ADIYLA YAZILI: bu dosyanin ICINE gercek bir `Command::new("node")`
/// konursa kapi onu GORMEZ. Kabul edilebilir, cunku burasi kapinin kendisi —
/// buraya node cagirmak, kapiyi silmekle ayni bilincli eylemdir. Muafiyetin
/// TEK bir yol olmasi asagida IDDIA olarak tutuluyor ki liste sessizce
/// buyumesin.
const TARAYICININ_KENDI_KAYNAGI: &str = "rust/crates/cli/tests/noderuntime.rs";

/// Bir `package.json`in `scripts` blogundaki komutlar.
///
/// Blok DISINA bakilmiyor: bir bagimliligin surumu ya da bir `description`
/// alani komut degildir, ve onlari da taramak kapiyi duzyaziya bagimli
/// kilardi.
fn package_scripts(src: &str) -> Vec<String> {
    let Some(baslangic) = src.find("\"scripts\"") else {
        return Vec::new();
    };
    let Some(acilis) = src[baslangic..].find('{') else {
        return Vec::new();
    };
    let govde_baslangic = baslangic + acilis + 1;
    let Some(kapanis) = src[govde_baslangic..].find('}') else {
        return Vec::new();
    };
    let govde = &src[govde_baslangic..govde_baslangic + kapanis];

    let mut out = Vec::new();
    for satir in govde.lines() {
        // `"ad": "komut"` — degeri ikinci tirnak ciftinden aliyoruz.
        let mut parcalar = satir.split('"');
        let (_bos, _ad, _ayrac, deger) = (
            parcalar.next(),
            parcalar.next(),
            parcalar.next(),
            parcalar.next(),
        );
        if let Some(deger) = deger {
            out.push(deger.to_string());
        }
    }
    out
}

#[test]
fn package_scripts_reads_the_command_not_the_name() {
    let src = "{\n  \"name\": \"node-thing\",\n  \"scripts\": {\n    \"test\": \"vitest run\",\n    \"gen\": \"node gen.mjs\"\n  },\n  \"dependencies\": { \"x\": \"node-fetch\" }\n}";
    let komutlar = package_scripts(src);
    assert_eq!(
        komutlar,
        vec!["vitest run".to_string(), "node gen.mjs".to_string()]
    );
    // `name` ve `dependencies` icindeki "node" bir komut DEGIL.
    assert!(!komutlar
        .iter()
        .any(|k| k.contains("node-thing") || k.contains("node-fetch")));
}

/// MUAFIYETIN KAPISI: taramadan DISLANAN tek bir yol var ve o yol GERCEKTEN
/// var. Iki sey birden tutuluyor:
///   * sabit bir YAZIM HATASI olamaz — dislanan yol izlenen dosyalar arasinda
///     bulunmali, yoksa dislama hicbir sey yapmiyor demektir ve kapi yine
///     kirmizi doner (sessiz bir "duzeltme" olurdu);
///   * dislama BIR TANE kalmali — bu testi gecmenin tek yolu listeyi
///     buyutmemek, cunku dislanacak ikinci bir dosya bu dosyada bir SABIT
///     olarak degil, ayri bir karar olarak gorunmeli.
#[test]
fn the_scanner_excludes_exactly_one_path_and_that_path_exists() {
    let dosyalar = tracked_files(&repo_root());
    assert!(
        dosyalar.iter().any(|d| d == TARAYICININ_KENDI_KAYNAGI),
        "dislanan yol izlenen dosyalar arasinda YOK: {TARAYICININ_KENDI_KAYNAGI} \
         — dislama hicbir sey yapmiyor",
    );
    // Dislama TEK bir `&str` sabiti; bir liste olsaydi bu iddia uzunluga
    // bakardi. Bicimi burada pinliyoruz ki bir sonraki el once buraya baksin.
    assert!(
        !TARAYICININ_KENDI_KAYNAGI.contains(','),
        "dislama TEK bir yol olmali"
    );
}

/// SINIFIN KAPISI: node'a bu depodan is verilmiyor.
#[test]
fn nothing_in_this_repo_hands_a_typescript_file_to_node() {
    let root = repo_root();
    let dosyalar = tracked_files(&root);
    assert!(
        dosyalar.len() > 200,
        "git yalnizca {} dosya saydi — tarayici yanlis koke bakiyor: {}",
        dosyalar.len(),
        root.display(),
    );

    let mut bulgular: BTreeSet<String> = BTreeSet::new();
    let mut okunan = 0usize;
    for yol in &dosyalar {
        // Cetvel kendini olcmez (bkz. TARAYICININ_KENDI_KAYNAGI).
        if yol == TARAYICININ_KENDI_KAYNAGI {
            continue;
        }
        let tam = root.join(yol);
        let Ok(icerik) = std::fs::read_to_string(&tam) else {
            continue;
        };
        okunan += 1;

        for (n, satir) in icerik.lines().enumerate() {
            if names_node_as_a_process(satir) {
                bulgular.insert(format!("{yol}:{}  {}", n + 1, satir.trim()));
            }
        }
        if yol.ends_with("package.json") {
            for komut in package_scripts(&icerik) {
                if runs_node_directly(&komut) {
                    bulgular.insert(format!("{yol}  (npm betigi)  {komut}"));
                }
            }
        }
    }
    assert!(
        okunan > 200,
        "yalnizca {okunan} dosya OKUNABILDI — tarama bos gecti"
    );

    assert!(
        bulgular.is_empty(),
        "BU DEPO ARTIK NODE'A IS VERIYOR — ve bu dosyanin dayandigi varsayim dustu:\n{}\n\n\
         BORC: `worker/` altindaki 11 `.ts` PARAMETRE OZELLIGI kullaniyor ve node'un\n\
         varsayilan (strip-only) kipi onu REDDEDIYOR (ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX).\n\
         Yeni giris noktasinin modul grafi o dosyalardan birine uzaniyorsa surec\n\
         MODUL YUKLENMEDEN olur — dusen bir test olarak degil, baslayamayan bir kapi olarak.\n\n\
         Olcum araci komsu depoda hazir:\n\
         \x20  node wapps-platform/crates/core/tests/node_runtime/strip_only.mjs <bu depo>\n\
         Onarim: alani BILDIR ve constructor govdesinde ata; bildirimi sinifin ILK\n\
         alani yap (tsc parametre ozelligini ilk alan olarak uretiyor, sona eklemek\n\
         `Object.keys` sirasini degistirir).",
        bulgular
            .iter()
            .map(|b| format!("  {b}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
