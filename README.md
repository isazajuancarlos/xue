<!-- SPDX-License-Identifier: LicenseRef-Propietario -->
# Xué

> Deterministic, offline MCP server that reveals hidden prompt injection in tool output — before your agent acts on it.

**[🇬🇧 English](#english) · [🇪🇸 Español](#español)**

**🛒 [Get Xué — $39 at the Xiliux store →](https://xiliux.lemonsqueezy.com)** · **[Consíguelo en la tienda Xiliux →](https://xiliux.lemonsqueezy.com)**

---

## English
<a name="english"></a>

**MCP server that reveals hidden prompt injection in tool output before your agent
acts.** Named for the Muisca sun god — the light that exposes what hides in the dark.

LLM agents read tool outputs, files and other MCP servers' responses as plain text.
Attackers hide instructions there in ways a human reviewer never sees: bidirectional
controls (Trojan Source, CVE-2021-42574), zero-width / invisible characters, Unicode
Tag ASCII smuggling, variation-selector steganography, and homoglyphs. Indirect
injection is now the majority of real-world agent attacks. Xué scans for exactly those
hidden carriers and reports them, with severity — it flags, it does not block.

Unlike model-based guardrails, Xué is **deterministic and offline**: it finds the
*invisible carrier*, not the meaning, in microseconds, with no model and no network.

### Tools
- **`scan_text`** — `{ text, path? }` → findings. `path` skips padding checks on
  generated files (`.min.js`, `.lock`, …).
- **`scan_json`** — `{ json }` → extracts every string from an arbitrary JSON value
  (e.g. another MCP server's raw response) and scans them.
- **`scan_file`** — `{ path }` → reads a local file (bounded, DoS-safe) and scans it.
- **`scan_mcp_manifest`** — `{ manifest }` → scans an MCP server's tool definitions
  for **tool poisoning**, attributing each finding to the specific tool.

Every call returns a human-readable `content` summary **and** machine-usable
`structuredContent` for gating in a pipeline:

```json
{ "clean": false, "highestSeverity": "high", "count": 2,
  "findings": [ { "class": "zero-width", "severity": "high", "line": 1,
                  "detail": "...", "sample": "ig<U+200B>nore" } ] }
```

### What it detects
| Class | Severity | What |
|---|---|---|
| `bidi` | high | Unicode bidirectional override/isolate controls (Trojan Source) |
| `tag-ascii` | high | Unicode Tag chars (U+E00xx) — invisible ASCII smuggling |
| `zero-width` | high | Zero-width / invisible characters embedded in words |
| `variation-selector` | high | Runs of variation selectors — steganographic byte hiding |
| `homoglyph` | medium | A token mixing alphabets (Latin + Cyrillic/Greek) — lookalike letters |
| `idn-punycode` | low | IDN/punycode host (`xn--`) — verify it is not a homograph domain |
| `horizontal-padding` | medium | Space/tab runs pushing text off screen |
| `vertical-padding` | low | Blank-line runs pushing text off screen |

Each finding carries a **line number** and a **sample with the hidden characters
made visible** (`ig<U+200B>nore`), so a reviewer sees exactly what the model saw. It
deliberately does **not** pattern-match injection phrases ("ignore previous
instructions"): a phrase catalog fires on legitimate security content.

### Run
```
cargo run          # speaks JSON-RPC 2.0 over stdio
cargo test         # 37 unit + 3 end-to-end (real binary over stdio)
```

Wire it into any MCP client as a stdio server pointing at the `xue` binary:

```json
{ "mcpServers": { "xue": { "command": "/path/to/xue" } } }
```

With Docker: `"command": "docker", "args": ["run", "-i", "--rm", "xue"]`.

#### Configuration (flags or env; flags win)
| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--disable a,b` | `XUE_DISABLE` | — | turn off detection classes |
| `--run-horizontal N` | `XUE_RUN_HORIZONTAL` | 300 | space/tab run threshold |
| `--run-vertical N` | `XUE_RUN_VERTICAL` | 40 | blank-line run threshold |
| `--run-selectors N` | `XUE_RUN_SELECTORS` | 3 | variation-selector run threshold |

`--help` / `--version` print and exit. Invalid config fails loudly (exit 2). Logs
go to **stderr**; stdout carries only JSON-RPC. No network, no telemetry.

### Design
Single static binary (musl → `scratch` image), one dependency (`serde_json`),
hand-rolled MCP stdio transport (JSON-RPC 2.0). Detection engine is a reusable
library (`xue` crate) so it can be embedded directly, not only via MCP.

### License / authorship
© Isaza Arenas. Proprietary. Detection core derived from the author's
`olfateador_ofuscacion` engine.

---

## Español
<a name="español"></a>

**Servidor MCP que revela la inyección de prompt oculta en la salida de las
herramientas antes de que tu agente actúe.** Lleva el nombre del dios sol muisca: la
luz que expone lo que se esconde en la oscuridad.

Los agentes LLM leen las salidas de herramientas, los archivos y las respuestas de
otros servidores MCP como texto plano. Los atacantes esconden ahí instrucciones de
formas que un revisor humano nunca ve: controles bidireccionales (Trojan Source,
CVE-2021-42574), caracteres de ancho cero / invisibles, contrabando de ASCII con
caracteres Tag de Unicode, esteganografía con selectores de variación y homóglifos.
La inyección indirecta es hoy la mayoría de los ataques reales contra agentes. Xué
busca exactamente esos portadores ocultos y los reporta, con severidad: marca, no
bloquea.

A diferencia de las barreras basadas en modelos, Xué es **determinista y sin
conexión**: encuentra el *portador invisible*, no el significado, en microsegundos,
sin modelo y sin red.

### Herramientas
- **`scan_text`** — `{ text, path? }` → hallazgos. `path` omite las comprobaciones de
  relleno en archivos generados (`.min.js`, `.lock`, …).
- **`scan_json`** — `{ json }` → extrae cada cadena de un valor JSON arbitrario
  (por ejemplo, la respuesta cruda de otro servidor MCP) y las escanea.
- **`scan_file`** — `{ path }` → lee un archivo local (acotado, a prueba de DoS) y lo
  escanea.
- **`scan_mcp_manifest`** — `{ manifest }` → escanea las definiciones de herramientas
  de un servidor MCP en busca de **envenenamiento de herramientas** (tool poisoning),
  atribuyendo cada hallazgo a la herramienta concreta.

Cada llamada devuelve un resumen legible por humanos en `content` **y** un
`structuredContent` utilizable por máquina para filtrar en una tubería:

```json
{ "clean": false, "highestSeverity": "high", "count": 2,
  "findings": [ { "class": "zero-width", "severity": "high", "line": 1,
                  "detail": "...", "sample": "ig<U+200B>nore" } ] }
```

### Qué detecta
| Clase | Severidad | Qué |
|---|---|---|
| `bidi` | high | Controles bidireccionales de anulación/aislamiento de Unicode (Trojan Source) |
| `tag-ascii` | high | Caracteres Tag de Unicode (U+E00xx) — contrabando de ASCII invisible |
| `zero-width` | high | Caracteres de ancho cero / invisibles incrustados en palabras |
| `variation-selector` | high | Series de selectores de variación — ocultación esteganográfica de bytes |
| `homoglyph` | medium | Un token que mezcla alfabetos (latino + cirílico/griego) — letras que se parecen |
| `idn-punycode` | low | Host IDN/punycode (`xn--`) — verifica que no sea un dominio homógrafo |
| `horizontal-padding` | medium | Series de espacios/tabulaciones que empujan el texto fuera de la pantalla |
| `vertical-padding` | low | Series de líneas en blanco que empujan el texto fuera de la pantalla |

Cada hallazgo lleva un **número de línea** y una **muestra con los caracteres ocultos
hechos visibles** (`ig<U+200B>nore`), para que un revisor vea exactamente lo que vio
el modelo. A propósito **no** busca por coincidencia de frases de inyección ("ignore
previous instructions"): un catálogo de frases dispara sobre contenido legítimo de
seguridad.

### Ejecutar
```
cargo run          # habla JSON-RPC 2.0 por stdio
cargo test         # 37 unit + 3 de extremo a extremo (binario real por stdio)
```

Conéctalo a cualquier cliente MCP como servidor stdio que apunte al binario `xue`:

```json
{ "mcpServers": { "xue": { "command": "/path/to/xue" } } }
```

Con Docker: `"command": "docker", "args": ["run", "-i", "--rm", "xue"]`.

#### Configuración (flags o env; los flags ganan)
| Flag | Env | Por defecto | Significado |
|---|---|---|---|
| `--disable a,b` | `XUE_DISABLE` | — | apaga clases de detección |
| `--run-horizontal N` | `XUE_RUN_HORIZONTAL` | 300 | umbral de serie de espacios/tabulaciones |
| `--run-vertical N` | `XUE_RUN_VERTICAL` | 40 | umbral de serie de líneas en blanco |
| `--run-selectors N` | `XUE_RUN_SELECTORS` | 3 | umbral de serie de selectores de variación |

`--help` / `--version` imprimen y salen. La configuración inválida falla ruidosamente
(salida 2). Los registros van a **stderr**; stdout lleva únicamente JSON-RPC. Sin red,
sin telemetría.

### Diseño
Un único binario estático (musl → imagen `scratch`), una sola dependencia
(`serde_json`), transporte MCP stdio hecho a mano (JSON-RPC 2.0). El motor de
detección es una biblioteca reutilizable (crate `xue`), así que puede empotrarse
directamente, no solo vía MCP.

### Licencia / autoría
© Isaza Arenas. Propietario. El núcleo de detección deriva del motor
`olfateador_ofuscacion` del autor.
