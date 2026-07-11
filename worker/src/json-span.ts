// Byte-exact JSON değer-aralığı tarayıcısı (§3.6.3 / COORD c). İmzalı bir body
// METNİNDEN bir değerin TAM ham alt-dizesini (iç boşluk dahil, çevre boşluk hariç)
// çıkarır — Go `json.RawMessage`'ın byte-exact saklama paritesi. Go, `rotation` ve
// ReceiptKey `jwk` gibi passthrough alanları RawMessage olarak body'de göründüğü
// baytlarla saklar ve `bytes.Equal` / `reflect.DeepEqual` ile byte-bayt karşılaştırır;
// JSON.parse ham baytları normalize ettiğinden (boşluk/format kaybolur), TS bu
// alanları imzalı body metninden elle tarayıp saklamalı. İki tüketici (manifest.ts
// rotation, trust.ts jwk) TEK kaynak kullansın diye buraya çıkarıldı — iki kopya
// arasında sessiz bir drift consensus-bug'ı olurdu.
//
// KATİ: bu tarayıcılar YALNIZCA JSON.parse'tan GEÇMİŞ (geçerli) body üzerinde çalışır;
// sözdizim doğrulaması JSON.parse'ta zaten yapılmıştır, burada yalnızca yapı taranır.

export function isJsonWs(c: string): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r";
}

export function skipJsonWs(s: string, i: number): number {
  while (i < s.length && isJsonWs(s[i])) i++;
  return i;
}

/** scanJsonString, s[i]==='"' konumundan kapanış tırnağından SONRAKİ indeksi döner. */
export function scanJsonString(s: string, i: number): number {
  let j = i + 1;
  while (j < s.length) {
    const ch = s[j];
    if (ch === "\\") {
      j += 2; // kaçış dizisi — bir sonraki karakteri atla
      continue;
    }
    if (ch === '"') return j + 1;
    j++;
  }
  return j; // sonlanmamış (geçerli JSON'da olmaz)
}

/**
 * scanJsonValue, önündeki boşluk atlanarak s'deki JSON değerini tarar ve
 * { start, end } döner: start = değerin ilk baytı (boşluk sonrası), end = değerden
 * HEMEN SONRAKİ indeks. String-farkında derinlik taraması (yalnızca yapı; içerik
 * JSON.parse'ta zaten doğrulandı). slice(start,end) = Go json.RawMessage baytları.
 */
export function scanJsonValue(s: string, i0: number): { start: number; end: number } {
  const start = skipJsonWs(s, i0);
  const first = s[start];
  if (first === '"') return { start, end: scanJsonString(s, start) };
  if (first !== "{" && first !== "[") {
    // primitif: number | true | false | null — sınırlayıcıya kadar
    let j = start;
    while (j < s.length) {
      const ch = s[j];
      if (ch === "," || ch === "}" || ch === "]" || isJsonWs(ch)) break;
      j++;
    }
    return { start, end: j };
  }
  let depth = 0;
  let j = start;
  let inStr = false;
  while (j < s.length) {
    const ch = s[j];
    if (inStr) {
      if (ch === "\\") {
        j += 2;
        continue;
      }
      if (ch === '"') inStr = false;
      j++;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      j++;
      continue;
    }
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") {
      depth--;
      if (depth === 0) {
        j++;
        break;
      }
    }
    j++;
  }
  return { start, end: j };
}

/**
 * findMemberValueSpan, s[objStart]==='{' olan bir OBJE'nin verilen anahtarının
 * değer aralığını döner (yoksa null). Yinelenen anahtarda SON eşleşme kazanır —
 * Go encoding/json (ve JSON.parse) last-wins semantiğiyle parite.
 */
export function findMemberValueSpan(s: string, objStart: number, key: string): { start: number; end: number } | null {
  let i = skipJsonWs(s, objStart + 1); // '{' sonrası
  let last: { start: number; end: number } | null = null;
  while (i < s.length && s[i] !== "}") {
    i = skipJsonWs(s, i);
    if (s[i] !== '"') break; // anahtar string değil (geçerli JSON'da olmaz)
    const kEnd = scanJsonString(s, i);
    const k = JSON.parse(s.slice(i, kEnd)) as string;
    i = skipJsonWs(s, kEnd);
    if (s[i] !== ":") break;
    const val = scanJsonValue(s, i + 1);
    if (k === key) last = val;
    i = skipJsonWs(s, val.end);
    if (s[i] === ",") {
      i++;
      continue;
    }
    break; // ',' değilse '}' (veya sonlanmış)
  }
  return last;
}
