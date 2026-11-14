// SPDX-License-Identifier: LicenseRef-Propietario
//! Xué — servidor MCP que revela ofuscación / inyección indirecta en salidas de
//! herramientas, texto y manifiestos MCP. Transporte: JSON-RPC 2.0 por stdio, un
//! mensaje JSON por línea. Sin telemetría, sin red, un solo binario.

use xue::config::Config;
use xue::mcp;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Tope de UNA línea leída de stdin. El transporte MCP es un mensaje JSON por
/// línea; `scan_file` ya se acota a 8 MiB (mcp.rs), así que una línea legítima
/// —que puede traer un `text`/`json` inline de unos pocos MB— cabe de sobra en
/// 16 MiB. Sin este tope, `.lines()` aloja la línea ENTERA (cientos de MB, o
/// /dev/zero sin '\n') antes de que MAX_ESCANEO (4 MiB) recorte nada → DoS de
/// memoria del proceso MCP. Se acota la lectura ANTES de materializar el `Value`.
const MAX_LINEA: u64 = 16 * 1024 * 1024;

enum Linea {
    /// Una línea completa (sin el '\n'/'\r' final), bajo el tope.
    Texto(String),
    /// La línea excedía MAX_LINEA; ya se descartó su resto hasta el próximo '\n'.
    Desbordada,
}

/// Lee una línea de `r` acotada a `max` bytes, SIN alojar más de ese tope. Si la
/// línea excede `max`, descarta el resto hasta el próximo '\n' usando el búfer
/// interno del lector (`fill_buf`/`consume`, sin alojar) y devuelve `Desbordada`.
/// `Ok(None)` = EOF. Un error de E/S o UTF-8 inválido se propaga como `Err`
/// (igual que el `.lines()` original, que rompía el bucle).
fn leer_linea_acotada(r: &mut impl BufRead, max: u64) -> io::Result<Option<Linea>> {
    let max = max as usize;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let trozo = r.fill_buf()?;
        if trozo.is_empty() {
            // EOF: nada leído => fin del stream; algo en buf => última línea sin '\n'.
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        match trozo.iter().position(|&b| b == b'\n') {
            // '\n' en este trozo: ¿cabe la línea entera bajo el tope?
            Some(pos) if buf.len() + pos < max => {
                buf.extend_from_slice(&trozo[..=pos]);
                r.consume(pos + 1);
                break;
            }
            // '\n' visible pero la línea excede el tope: descartarla hasta el '\n'.
            Some(pos) => {
                r.consume(pos + 1);
                return Ok(Some(Linea::Desbordada));
            }
            // Sin '\n' todavía: acumular si cabe; si no, descartar hasta el próximo '\n'.
            None => {
                let disp = trozo.len();
                if buf.len() + disp <= max {
                    buf.extend_from_slice(trozo);
                    r.consume(disp);
                } else {
                    r.consume(disp);
                    descartar_hasta_salto(r)?;
                    return Ok(Some(Linea::Desbordada));
                }
            }
        }
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    let s = String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(Linea::Texto(s)))
}

/// Consume bytes del lector hasta pasar el próximo '\n' (o EOF), SIN alojarlos:
/// solo avanza el búfer interno. Usado para tirar el resto de una línea desbordada.
fn descartar_hasta_salto(r: &mut impl BufRead) -> io::Result<()> {
    loop {
        let trozo = r.fill_buf()?;
        if trozo.is_empty() {
            return Ok(()); // EOF sin '\n' final
        }
        match trozo.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                r.consume(pos + 1);
                return Ok(());
            }
            None => {
                let len = trozo.len();
                r.consume(len);
            }
        }
    }
}

const AYUDA: &str = "\
Xué — MCP anti-obfuscation / indirect-injection server

USAGE:
  xue [options]               start the MCP server (stdio)

OPTIONS:
  --disable <a,b,...>         disable detection classes
                              (bidi, tag-ascii, zero-width, variation-selector,
                               homoglyph, horizontal-padding, vertical-padding)
  --run-horizontal <N>        consecutive space/tab run threshold (default 300)
  --run-vertical <N>          consecutive blank-line run threshold (default 40)
  --run-selectors <N>         consecutive variation-selector run threshold (default 3)
  --help                      show this help
  --version                   show the version

ENVIRONMENT (equivalent; flags win):
  XUE_DISABLE, XUE_RUN_HORIZONTAL, XUE_RUN_VERTICAL, XUE_RUN_SELECTORS";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{AYUDA}");
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("xue {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let cfg = match Config::desde(&args, |k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xue: invalid configuration: {e}");
            std::process::exit(2);
        }
    };

    // Logs SIEMPRE a stderr: stdout está reservado para JSON-RPC (spec MCP).
    eprintln!("xue {} — MCP stdio ready", env!("CARGO_PKG_VERSION"));

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut salida = stdout.lock();

    let mut entrada = stdin.lock();
    loop {
        let linea = match leer_linea_acotada(&mut entrada, MAX_LINEA) {
            Ok(Some(Linea::Texto(l))) => l,
            Ok(Some(Linea::Desbordada)) => {
                // Línea > MAX_LINEA: no se alojó entera; respondemos error y
                // seguimos (el resto ya se descartó hasta el próximo '\n').
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32700, "message": "request line exceeds the 16 MiB limit; discarded"}
                });
                if writeln!(salida, "{resp}").is_err() || salida.flush().is_err() {
                    break;
                }
                continue;
            }
            Ok(None) => break, // EOF
            Err(_) => break,   // E/S o UTF-8 inválido (como el `.lines()` original)
        };
        if linea.trim().is_empty() {
            continue;
        }
        let respuesta: Option<Value> = match serde_json::from_str::<Value>(&linea) {
            Ok(req) => mcp::manejar(&req, &cfg),
            Err(e) => Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": format!("invalid JSON: {e}")}
            })),
        };
        if let Some(resp) = respuesta {
            if writeln!(salida, "{resp}").is_err() || salida.flush().is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::io::Cursor;

    fn leer(c: &mut Cursor<&[u8]>, max: u64) -> Option<Linea> {
        leer_linea_acotada(c, max).unwrap()
    }

    // --- Defecto 2 (DoS de memoria): la lectura se acota ANTES de materializar ---
    // Caso ROJO/VERDE a la vez: con max=8, una línea > 8 bytes NO panica, devuelve
    // Desbordada SIN alojar el resto, y la línea SIGUIENTE se lee intacta (prueba
    // de que el descarte paró EXACTO en el '\n', no se comió la cola). Una línea
    // normal se procesa. Esto discrimina: sin el tope, no existiría `Desbordada` y
    // la línea gigante se alojaría entera.
    #[test]
    fn linea_normal_pasa_larga_se_desborda_y_recupera() {
        let datos = b"hello\nthisislongline\nok\n";
        let mut c = Cursor::new(&datos[..]);
        assert!(matches!(leer(&mut c, 8), Some(Linea::Texto(s)) if s == "hello"));
        assert!(matches!(leer(&mut c, 8), Some(Linea::Desbordada)));
        assert!(matches!(leer(&mut c, 8), Some(Linea::Texto(s)) if s == "ok"));
        assert!(leer(&mut c, 8).is_none()); // EOF
    }

    #[test]
    fn ultima_linea_sin_salto_bajo_tope_pasa() {
        let datos = b"x";
        let mut c = Cursor::new(&datos[..]);
        assert!(matches!(leer(&mut c, 8), Some(Linea::Texto(s)) if s == "x"));
        assert!(leer(&mut c, 8).is_none());
    }

    #[test]
    fn crlf_se_recorta_igual_que_lines() {
        let datos = b"abc\r\n";
        let mut c = Cursor::new(&datos[..]);
        assert!(matches!(leer(&mut c, 64), Some(Linea::Texto(s)) if s == "abc"));
    }

    #[test]
    fn linea_al_borde_del_tope_cabe() {
        // 7 bytes + '\n' = 8 == max: cabe, no se marca desbordada.
        let datos = b"1234567\n";
        let mut c = Cursor::new(&datos[..]);
        assert!(matches!(leer(&mut c, 8), Some(Linea::Texto(s)) if s == "1234567"));
    }
}
