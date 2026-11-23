// isLoopbackRedirect must agree with the Rust gate (is_loopback_http in
// crates/workers/src/gate/claims.rs): the same vectors, the same answers. A WHATWG URL
// parser normalises hosts and schemes, so it admits forms the strict check must refuse.

import { describe, it, expect } from "vitest";
import { isLoopbackRedirect } from "../src/auth.js";

const accepted = [
  "http://127.0.0.1:5555/callback",
  "http://127.0.0.1/callback",
  "http://localhost:8080/cb?x=1",
  "http://localhost",
  "http://127.0.0.1:5555",
];

const refused = [
  // The Rust vectors.
  "https://evil.example/cb",
  "https://127.0.0.1:5555/cb",
  "http://127.0.0.1.evil.example/cb",
  "http://localhost.evil.example/cb",
  "http://evil.example/127.0.0.1",
  "http://evil.example/?h=localhost",
  "http://127.0.0.1@evil.example/cb",
  "http://localhost:80@evil.example/",
  "http://127.0.0.1\\@evil.example/",
  "http://evil.example#@127.0.0.1/",
  "http://127.0.0.1:/cb",
  "http://127.0.0.1:99999/cb",
  "http://127.0.0.1:5a/cb",
  "http://[::1]:5555/cb",
  "http://0.0.0.0/cb",
  "http:// 127.0.0.1/cb",
  "HTTP://127.0.0.1/cb",
  "127.0.0.1:5555/cb",
  "http:/127.0.0.1/cb",
  "",
  // Forms the WHATWG URL parser normalises into a loopback host.
  "http://127.1/",
  "http://0x7f.1/",
  "http://2130706433/",
  "http://u:p@127.0.0.1/",
  "http://127.0.0.1\\x",
  "http://LOCALHOST/",
  "http://127.0.0.1\t/cb",
  "http://127.0.0.1/\ncb",
  "http://127.0.0.1\u0085/cb",
  "http://127.0.0.1\u007f/cb",
  "http://localhost.:80/",
];

describe("isLoopbackRedirect agrees with the Rust is_loopback_http", () => {
  for (const uri of accepted) it(`accepts ${JSON.stringify(uri)}`, () => expect(isLoopbackRedirect(uri)).toBe(true));
  for (const uri of refused) it(`refuses ${JSON.stringify(uri)}`, () => expect(isLoopbackRedirect(uri)).toBe(false));
  for (const v of [undefined, null, 5555, ["http://127.0.0.1/cb"], {}]) {
    it(`refuses a non-string ${JSON.stringify(v)}`, () => expect(isLoopbackRedirect(v)).toBe(false));
  }
});
