// SPDX-License-Identifier: LicenseRef-Propietario
//! Configuración por clase y umbrales. Se lee de variables de entorno (como las
//! pone un cliente MCP en su config) y de argumentos CLI, que ganan sobre el
//! entorno. Sin dependencias: parseo a mano.
//!
//! Cascada (D19): por defecto TODO activo con umbrales sensatos; el llamante
//! desactiva o afina lo que no use. Nadie configura lo que no necesita.

#[derive(Debug, Clone)]
pub struct Config {
    deshabilitadas: Vec<String>,
    pub run_horizontal: usize,
    pub run_vertical: usize,
    pub run_selectores: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            deshabilitadas: Vec::new(),
            run_horizontal: 300,
            run_vertical: 40,
            run_selectores: 3,
        }
    }
}

/// Nombres de clase válidos (para validar `--disable` y no callar un typo, D20).
pub const CLASES: [&str; 8] = [
    "bidi",
    "tag-ascii",
    "zero-width",
    "variation-selector",
    "homoglyph",
    "idn-punycode",
    "horizontal-padding",
    "vertical-padding",
];

impl Config {
    /// ¿Se emite esta clase de hallazgo?
    pub fn activa(&self, clase: &str) -> bool {
        !self.deshabilitadas.iter().any(|c| c == clase)
    }

    fn fijar_deshabilitadas(&mut self, csv: &str) -> Result<(), String> {
        let mut out = Vec::new();
        for bruto in csv.split(',') {
            let c = bruto.trim();
            if c.is_empty() {
                continue;
            }
            if !CLASES.contains(&c) {
                return Err(format!(
                    "unknown class in --disable: '{c}' (valid: {})",
                    CLASES.join(", ")
                ));
            }
            out.push(c.to_string());
        }
        self.deshabilitadas = out;
        Ok(())
    }

    /// Construye desde entorno + argumentos. Args ganan sobre entorno.
    /// Devuelve Err con mensaje si algo es inválido (falla ruidoso, D20).
    pub fn desde(
        args: &[String],
        getenv: impl Fn(&str) -> Option<String>,
    ) -> Result<Config, String> {
        let mut c = Config::default();

        if let Some(v) = getenv("XUE_DISABLE") {
            c.fijar_deshabilitadas(&v)?;
        }
        for (var, campo) in [
            ("XUE_RUN_HORIZONTAL", 0),
            ("XUE_RUN_VERTICAL", 1),
            ("XUE_RUN_SELECTORS", 2),
        ] {
            if let Some(v) = getenv(var) {
                let n: usize = v
                    .parse()
                    .map_err(|_| format!("{var} is not an integer: '{v}'"))?;
                c.set_umbral(campo, n);
            }
        }

        let mut i = 0;
        while i < args.len() {
            let necesita_valor = |i: usize| -> Result<&String, String> {
                args.get(i + 1)
                    .ok_or_else(|| format!("missing value for {}", args[i]))
            };
            match args[i].as_str() {
                "--disable" => {
                    c.fijar_deshabilitadas(necesita_valor(i)?)?;
                    i += 1;
                }
                "--run-horizontal" => {
                    c.run_horizontal = parse_usize(necesita_valor(i)?)?;
                    i += 1;
                }
                "--run-vertical" => {
                    c.run_vertical = parse_usize(necesita_valor(i)?)?;
                    i += 1;
                }
                "--run-selectors" => {
                    c.run_selectores = parse_usize(necesita_valor(i)?)?;
                    i += 1;
                }
                otro => return Err(format!("unknown argument: '{otro}' (use --help)")),
            }
            i += 1;
        }
        c.validar()?;
        Ok(c)
    }

    /// Una sola regla para los tres umbrales de "racha consecutiva" (D23: la regla
    /// se escribe una vez, no en cada sitio de parseo). Un umbral de 0 no tiene
    /// sentido —una racha de ≥0 de cualquier cosa es SIEMPRE cierta, lo que
    /// convierte el detector en un falso positivo permanente— y en
    /// `run_selectores` además hace `chars[sel_i]` sobre texto vacío → índice
    /// fuera de rango → PÁNICO del proceso MCP (ver deteccion.rs). Se rechaza al
    /// construir la config para no arrancar con config inválida (D20, igual que
    /// main.rs:45), en vez de panicar en caliente. El mínimo es 1 para los tres.
    fn validar(&self) -> Result<(), String> {
        for (nombre, valor) in [
            ("run-horizontal", self.run_horizontal),
            ("run-vertical", self.run_vertical),
            ("run-selectors", self.run_selectores),
        ] {
            if valor < 1 {
                return Err(format!("{nombre} must be >= 1 (got {valor})"));
            }
        }
        Ok(())
    }

    fn set_umbral(&mut self, campo: u8, n: usize) {
        match campo {
            0 => self.run_horizontal = n,
            1 => self.run_vertical = n,
            _ => self.run_selectores = n,
        }
    }
}

fn parse_usize(s: &str) -> Result<usize, String> {
    s.parse().map_err(|_| format!("not an integer: '{s}'"))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn sin_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn por_defecto_todo_activo() {
        let c = Config::default();
        assert!(CLASES.iter().all(|k| c.activa(k)));
    }

    #[test]
    fn disable_por_arg_desactiva() {
        let args = vec!["--disable".to_string(), "homoglyph,vertical-padding".to_string()];
        let c = Config::desde(&args, sin_env).unwrap();
        assert!(!c.activa("homoglyph"));
        assert!(!c.activa("vertical-padding"));
        assert!(c.activa("bidi"));
    }

    #[test]
    fn clase_invalida_falla_ruidoso() {
        let args = vec!["--disable".to_string(), "no-existe".to_string()];
        assert!(Config::desde(&args, sin_env).is_err());
    }

    #[test]
    fn umbral_por_arg() {
        let args = vec!["--run-selectors".to_string(), "8".to_string()];
        let c = Config::desde(&args, sin_env).unwrap();
        assert_eq!(c.run_selectores, 8);
    }

    #[test]
    fn arg_gana_sobre_env() {
        let env = |k: &str| (k == "XUE_RUN_VERTICAL").then(|| "10".to_string());
        let args = vec!["--run-vertical".to_string(), "99".to_string()];
        let c = Config::desde(&args, env).unwrap();
        assert_eq!(c.run_vertical, 99);
    }

    #[test]
    fn arg_desconocido_falla() {
        let args = vec!["--turbo".to_string()];
        assert!(Config::desde(&args, sin_env).is_err());
    }

    // --- Defecto 1 (D20): umbral de racha < 1 no arranca ---
    // Caso ROJO: sin el chequeo en `validar`, `--run-selectors 0` se aceptaría y
    // luego panicaría en deteccion.rs sobre texto vacío. Debe fallar al construir.
    #[test]
    fn run_selectores_cero_por_arg_falla() {
        let args = vec!["--run-selectors".to_string(), "0".to_string()];
        assert!(Config::desde(&args, sin_env).is_err());
    }

    #[test]
    fn run_selectores_cero_por_env_falla() {
        let env = |k: &str| (k == "XUE_RUN_SELECTORS").then(|| "0".to_string());
        assert!(Config::desde(&[], env).is_err());
    }

    // El mismo umbral-análogo: los tres a 0 fallan (una racha de ≥0 siempre dispara).
    #[test]
    fn run_horizontal_y_vertical_cero_fallan() {
        let h = vec!["--run-horizontal".to_string(), "0".to_string()];
        assert!(Config::desde(&h, sin_env).is_err());
        let v = vec!["--run-vertical".to_string(), "0".to_string()];
        assert!(Config::desde(&v, sin_env).is_err());
    }

    // Caso VERDE: 1 y 3 (y el default) son válidos — no sobre-cerramos (D21).
    #[test]
    fn run_selectores_uno_y_tres_ok() {
        for n in ["1", "3"] {
            let args = vec!["--run-selectors".to_string(), n.to_string()];
            let c = Config::desde(&args, sin_env).unwrap();
            assert_eq!(c.run_selectores, n.parse::<usize>().unwrap());
        }
        assert!(Config::desde(&[], sin_env).is_ok()); // default run_selectores=3
    }
}
