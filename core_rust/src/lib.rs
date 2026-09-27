use pyo3::prelude::*;
use std::collections::HashSet;
use std::sync::Mutex;

/// Gerenciador de Quarentena e Tarpit em memória de alta velocidade
#[pyclass]
pub struct QuarantineManager {
    quarantined_ips: Mutex<HashSet<String>>,
}

#[pymethods]
impl QuarantineManager {
    #[new]
    fn new() -> Self {
        QuarantineManager {
            quarantined_ips: Mutex::new(HashSet::new()),
        }
    }

    /// Adiciona um IP à Quarentena
    fn isolate_ip(&self, ip: String) -> PyResult<bool> {
        let mut ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.insert(ip))
    }

    /// Remove um IP da Quarentena
    fn release_ip(&self, ip: String) -> PyResult<bool> {
        let mut ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.remove(&ip))
    }

    /// Checa se o IP está em quarentena
    fn is_quarantined(&self, ip: String) -> PyResult<bool> {
        let ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.contains(&ip))
    }

    /// Lista todos os IPs isolados
    fn get_isolated_ips(&self) -> PyResult<Vec<String>> {
        let ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.iter().cloned().collect())
    }
}

/// Calcula a Entropia de Shannon do payload bruto (bytes)
#[pyfunction]
fn calculate_entropy(payload: &[u8]) -> PyResult<f64> {
    if payload.is_empty() {
        return Ok(0.0);
    }

    let mut counts = [0usize; 256];
    for &byte in payload {
        counts[byte as usize] += 1;
    }

    let len = payload.len() as f64;
    let mut entropy = 0.0;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    Ok(entropy)
}

/// Módulo Python exposto via PyO3 0.21+ (API Bound)
#[pymodule]
fn core_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_entropy, m)?)?;
    m.add_class::<QuarantineManager>()?;
    Ok(())
}