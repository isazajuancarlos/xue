# Xué — servidor MCP (`xue`)

Config general: `~/.claude/CLAUDE.md`. Aquí solo lo propio de este proyecto.

## Qué es
Servidor **MCP** (JSON-RPC 2.0 por stdio) que **revela ofuscación / inyección
indirecta** en salidas de herramientas, texto y **manifiestos MCP** (tool poisoning).
8 clases con severidad; marca, no bloquea. Tools: `scan_text`, `scan_json`,
`scan_file`, `scan_mcp_manifest`. Nombre: dios sol muisca (la luz que expone).

Es el **lado-defensa** de la veta red-team-IA (edge validado por juez, Gray Swan
2026-09-25) llevado a producto; candidato a monetizar en marketplace de MCP
(publicar = visto bueno de Juan, cada vez — solo-local).

## Origen del motor (D9)
`src/deteccion.rs` reusa y amplía el motor del hook
`~/.claude/hooks/olfateador_ofuscacion` (estudio NVIDIA/SkillSpector). Dos
consumidores (hook + este MCP); al tercero, extraer a crate compartida (no migrar
el hook vivo por decreto, D21).

## Correr / probar
- Servidor: `cargo run` (stdin/stdout). `--help`, `--version`.
- Pruebas: `cargo test` (37 unit + 3 E2E que arrancan el binario real, D28).
- Puerta: `cargo clippy -- -D warnings` (lints de nacimiento D26).
- Config: flags o env `XUE_*` (flags ganan); `--disable <clases>`, `--run-*`.

## Estado (v0.3.0)
- lib + bin (motor reusable, D9); 8 clases con severidad; 4 tools; config por
  clase y umbrales; transporte MCP endurecido (negociación de versión, logs a
  stderr, códigos JSON-RPC); `scan_file` con lectura acotada (DoS-safe); 40 pruebas
  verde; clippy limpio; Dockerfile (scratch). Ficha: `comercial/xue-listado.md`.
- **rmcp NO adoptado** a propósito: arrastra tokio+schemars y mata el foso
  (offline/binario único/1 dependencia); el transporte a mano ya cumple el espec
  MCP-stdio para un servidor de tools.

## Pendiente
- v0.4: tabla Unicode de confusables completa (homoglifo de un solo alfabeto).
- PUBLICAR en marketplace = visto bueno explícito, cada vez (solo-local).
- Registrar la propiedad en `MAPA.md` (nombre ya fijado: xue).
