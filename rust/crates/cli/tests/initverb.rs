// `secrets init` — bu dilimin en farkli fiili: `.wapps.yaml` OKUMUYOR, YAZIYOR.
//
// Iki sey olculuyor, ve ikisi de ayri ayri gerekli:
//
//  1. GIDIS-DONUS: yazdigimiz dosya KENDI ayristiricimiz tarafindan okunabilir
//     olmali. Ayristiricinin kabul ettigi kume ile ureticinin yazdigi sekil
//     ayrisirsa, `init` calistiran bir operator hemen ardindan "config: ..."
//     hatasi alirdi — ve bunu ancak sahada gorurdu.
//  2. BAYT ESITLIGI: Go'nun urettigi dosyayla BIREBIR ayni. Bu dosya bir
//     INSANIN duzenledigi bir sablon; yorum satirlari ve bosluklar sozlesmenin
//     parcasi. "Ayni anlamda ama farkli yazilmis" bir YAML burada yeterli
//     DEGIL: iki ikili ayni depoda donusumlu kosuyor ve bir fark, gurultulu
//     bir git diff'i olarak operatorun onune duserdi.
use wapps::initverb;

// GO_TEMPLATE, Go ikilisinden OLCULEN baytlardir (tahmin edilmedi):
// writeWappsYAMLStore'un ciktisi, sahte gate altinda pty ile calistirilip
// dosyadan okundu. Proje adi disinda hicbir sey degiskenlik tasimiyor.
const GO_TEMPLATE: &str = "# wapps-cli configuration\n\
# Docs: https://github.com/wappsdev/wapps-cli\n\
\n\
version: 2\n\
# The project this repo reads from in the secrets gate.\n\
project: myproj\n\
\n\
# Optional consumption targets. 'wapps secrets apply' materializes these\n\
# from the store — atomic, mode 0600, idempotent. Gitignore them.\n\
# targets:\n\
#   - path: .env.local\n\
#     prefix: \"\"\n";

#[test]
fn the_generated_file_is_byte_identical_to_the_go_template() {
    let got = initverb::render("myproj");
    assert_eq!(got, GO_TEMPLATE, "uretilen sablon Go'nunkinden BAYT olarak ayrisiyor");
}

// GIDIS-DONUS: kendi ayristiricimiz kendi ciktimizi okuyabilmeli.
#[test]
fn the_generated_file_parses_with_our_own_parser() {
    let raw = initverb::render("navlun-app");
    let cfg = wapps::wappsyaml::parse(raw.as_bytes())
        .expect("urettigimiz dosya kendi ayristiricimizdan gecmeli");
    assert_eq!(cfg.project, "navlun-app");
    assert_eq!(cfg.version, 2);
    assert_eq!(cfg.backend, wapps::wappsyaml::BACKEND_STORE);
    // `targets:` blogu YORUMDA — yani bos gelmeli. Yorum isaretini dusuren bir
    // sablon degisikligi `apply`i sessizce farkli davrandirirdi.
    assert!(cfg.targets.is_empty(), "sablondaki targets blogu YORUM olmali");
}

#[test]
fn init_writes_exactly_one_file_and_names_the_project() {
    let dir = tempdir("init-writes");
    let out = initverb::run(dir.to_str().unwrap(), "myproj", false).expect("init basarili olmali");
    let entries: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, [".wapps.yaml"], "init YALNIZCA .wapps.yaml yazmali");
    assert!(out.contains("wapps init complete"), "cikti: {out}");
    let _ = std::fs::remove_dir_all(&dir);
}

// Proje adi verilmezse DIZIN adina duser.
#[test]
fn an_absent_project_name_falls_back_to_the_directory_name() {
    let base = tempdir("init-dirname");
    let dir = base.join("navlun-app");
    std::fs::create_dir_all(&dir).unwrap();
    initverb::run(dir.to_str().unwrap(), "", false).expect("init");
    let raw = std::fs::read_to_string(dir.join(".wapps.yaml")).unwrap();
    let cfg = wapps::wappsyaml::parse(raw.as_bytes()).unwrap();
    assert_eq!(cfg.project, "navlun-app");
    let _ = std::fs::remove_dir_all(&base);
}

// Mevcut bir config --force OLMADAN asla ezilmez, ve reddedilen bir init
// dosyaya DOKUNMAZ.
#[test]
fn an_existing_config_is_never_clobbered_without_force() {
    let dir = tempdir("init-clobber");
    let path = dir.join(".wapps.yaml");
    std::fs::write(&path, "version: 2\nproject: original\n").unwrap();

    let err = initverb::run(dir.to_str().unwrap(), "other", false)
        .expect_err("init mevcut dosyayi ezmeyi REDDETMELI");
    assert!(err.contains("already exists"), "hata metni: {err}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "version: 2\nproject: original\n",
        "reddedilen init dosyaya DOKUNMAMALI"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn force_overwrites_an_existing_config() {
    let dir = tempdir("init-force");
    let path = dir.join(".wapps.yaml");
    std::fs::write(&path, "version: 2\nproject: original\n").unwrap();
    initverb::run(dir.to_str().unwrap(), "replacement", true).expect("--force init");
    let cfg = wapps::wappsyaml::parse(std::fs::read(&path).unwrap().as_slice()).unwrap();
    assert_eq!(cfg.project, "replacement");
    let _ = std::fs::remove_dir_all(&dir);
}

// tempdir, depo AGACININ DISINDA bir calisma dizini verir.
fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
