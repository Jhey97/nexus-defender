use pyo3::prelude::*;

/// Calcula a Entropia de Shannon do payload bruto (bytes)
#[pyfunction]
pub fn calculate_entropy(payload: &[u8]) -> PyResult<f64> {
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