// `secrets list` ve `projects list` — ADLARI basan iki fiil, DEGER asla.
//
// Ikisi ayni sinifta ama SIRALAMALARI kasitli olarak FARKLI, ve bu fark
// olculuyor:
//
//   * `secrets list` anahtar adlarini ISTEMCIDE siraliyor (Go: sort.Strings).
//   * `projects list` sunucudan geleni AYNEN basiyor — istemci kendi kendine
//     eleme ya da siralama YAPMAZ. Filtreleme SUNUCUDA (principal'in read
//     grant'ina gore); istemcide bir sort eklemek, sunucunun sirasinin bir
//     anlam tasidigi durumda onu sessizce yok ederdi.
use wapps::listverb;
use wapps::projectsverb;

#[test]
fn key_names_are_sorted_by_the_client() {
    let names = vec![
        "ZED".to_string(),
        "ALPHA".to_string(),
        "middle".to_string(),
        "BETA".to_string(),
    ];
    assert_eq!(listverb::render(&names), "ALPHA\nBETA\nZED\nmiddle\n");
}

// Siralama BAYT duzeyinde (Go sort.Strings) — yerel ayara gore DEGIL. Buyuk
// harfler kucuklerden once gelir; locale-duyarli bir sort burada ayrisirdi.
#[test]
fn the_sort_is_bytewise_not_locale_aware() {
    let names = vec!["b".to_string(), "A".to_string(), "a".to_string(), "B".to_string()];
    assert_eq!(listverb::render(&names), "A\nB\na\nb\n");
}

#[test]
fn an_empty_key_set_prints_nothing_and_is_not_an_error() {
    assert_eq!(listverb::render(&[]), "");
}

#[test]
fn project_names_keep_the_server_order() {
    let projects = vec!["vaulter".to_string(), "lumira".to_string(), "navlun-app".to_string()];
    assert_eq!(
        projectsverb::render(&projects),
        "vaulter\nlumira\nnavlun-app\n",
        "projects list sunucu sirasini BOZMAMALI"
    );
}

#[test]
fn an_empty_project_list_prints_nothing_and_is_not_an_error() {
    assert_eq!(projectsverb::render(&[]), "");
}
