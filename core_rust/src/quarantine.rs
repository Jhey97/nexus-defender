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
    pub fn new() -> Self {
        QuarantineManager {
            quarantined_ips: Mutex::new(HashSet::new()),
        }
    }

    /// Adiciona um IP à Quarentena
    pub fn isolate_ip(&self, ip: String) -> PyResult<bool> {
        let mut ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.insert(ip))
    }

    /// Remove um IP da Quarentena
    pub fn release_ip(&self, ip: String) -> PyResult<bool> {
        let mut ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.remove(&ip))
    }

    /// Checa se o IP está em quarentena
    pub fn is_quarantined(&self, ip: String) -> PyResult<bool> {
        let ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.contains(&ip))
    }

    /// Lista todos os IPs isolados
    pub fn get_isolated_ips(&self) -> PyResult<Vec<String>> {
        let ips = self.quarantined_ips.lock().unwrap();
        Ok(ips.iter().cloned().collect())
    }
}