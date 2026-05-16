//! PK / VK lifecycle: load from disk if present, otherwise run
//! trusted setup and persist.
//!
//! Each registered circuit gets a `CircuitKeys { pk, vk }` held in
//! a `Registry` indexed by the circuit's string id. Handlers reach
//! in via the id from the URL path; an unknown id is the 404 case.
//!
//! ## Layout on disk
//!
//! ```text
//! <keys_dir>/
//!   pedersen_opens_to.pk
//!   pedersen_opens_to.vk
//! ```
//!
//! Bytes are arkworks' compressed canonical encoding (the same
//! `serialize_compressed` / `deserialize_compressed` the `prover`
//! crate exposes). A future variant might split PK across files
//! for streaming reads, but for one ~10MB key, a single file is
//! fine.
//!
//! ## Setup randomness
//!
//! Uses `ark_std::test_rng()`. Reproducible, deterministic,
//! suitable for development. **Production needs a real ceremony**;
//! the stack spec calls this out as a future doc.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use circuits::pedersen_opens_to::PedersenOpensTo;
use prover::{
    deserialize_pk, deserialize_vk, serialize_pk, serialize_vk, setup,
    CircuitProvingKey, CircuitVerifyingKey,
};

/// PK + VK for one circuit. The PK is wrapped in `Arc` so request
/// handlers can clone the handle cheaply; the VK is small enough
/// to clone directly when needed.
#[derive(Clone)]
pub struct CircuitKeys {
    pub pk: Arc<CircuitProvingKey>,
    pub vk: CircuitVerifyingKey,
}

/// Lookup table from circuit id to its `(PK, VK)` pair. The
/// server holds one `Arc<Registry>` and clones the handle into
/// every request handler.
pub struct Registry {
    inner: HashMap<&'static str, CircuitKeys>,
}

impl Registry {
    /// Get the keys for a circuit id, if registered.
    pub fn get(&self, id: &str) -> Option<CircuitKeys> {
        self.inner.get(id).cloned()
    }
}

/// Build the registry. For each circuit, try to load `(pk, vk)`
/// from `<keys_dir>/<id>.{pk,vk}`; if missing, run trusted setup
/// and write the artifacts.
///
/// This is the only function that runs Groth16 setup in the
/// server. Setup is heavy (tens of seconds for the
/// `pedersen_opens_to` circuit in release) but happens at most
/// once per circuit per deployment — every subsequent boot reads
/// from disk.
///
/// Adding a new circuit means: one more `load_or_setup_<circuit>`
/// line below, one more `inner.insert(...)` row. The discipline
/// shows here intentionally — the per-circuit boot work is
/// duplicated until the third circuit makes a trait worth it.
pub fn build(keys_dir: &Path) -> std::io::Result<Registry> {
    fs::create_dir_all(keys_dir)?;

    let mut inner: HashMap<&'static str, CircuitKeys> = HashMap::new();

    // --- pedersen_opens_to ---
    let pedersen_keys = load_or_setup_pedersen_opens_to(keys_dir)?;
    inner.insert("pedersen_opens_to", pedersen_keys);

    Ok(Registry { inner })
}

/// Load `pedersen_opens_to` keys from disk, or run setup if
/// missing.
fn load_or_setup_pedersen_opens_to(
    keys_dir: &Path,
) -> std::io::Result<CircuitKeys> {
    let pk_path = keys_dir.join("pedersen_opens_to.pk");
    let vk_path = keys_dir.join("pedersen_opens_to.vk");

    if pk_path.exists() && vk_path.exists() {
        println!("[keys] loading pedersen_opens_to from disk");
        let pk_bytes = fs::read(&pk_path)?;
        let vk_bytes = fs::read(&vk_path)?;
        let pk = deserialize_pk(&pk_bytes)
            .map_err(|e| io_err(format!("pedersen_opens_to PK deser: {e}")))?;
        let vk = deserialize_vk(&vk_bytes)
            .map_err(|e| io_err(format!("pedersen_opens_to VK deser: {e}")))?;
        return Ok(CircuitKeys {
            pk: Arc::new(pk),
            vk,
        });
    }

    println!("[keys] running setup for pedersen_opens_to (one-shot)");
    // Dev setup: a fixed-seed StdRng for reproducibility across
    // boot cycles. Production needs a real ceremony, called out
    // in `specs/zk/stack.md`. StdRng satisfies `CryptoRng` so the
    // `prover::setup` bound holds.
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let (pk, vk) = setup(PedersenOpensTo::empty(), &mut rng)
        .map_err(|e| io_err(format!("pedersen_opens_to setup: {e}")))?;

    let pk_bytes = serialize_pk(&pk)
        .map_err(|e| io_err(format!("pedersen_opens_to PK ser: {e}")))?;
    let vk_bytes = serialize_vk(&vk)
        .map_err(|e| io_err(format!("pedersen_opens_to VK ser: {e}")))?;
    fs::write(&pk_path, &pk_bytes)?;
    fs::write(&vk_path, &vk_bytes)?;
    println!(
        "[keys] wrote {} ({} bytes) and {} ({} bytes)",
        pk_path.display(),
        pk_bytes.len(),
        vk_path.display(),
        vk_bytes.len(),
    );

    Ok(CircuitKeys {
        pk: Arc::new(pk),
        vk,
    })
}

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

/// Default keys directory: `./keys/` relative to the working
/// directory the server was launched from. Production deployments
/// override via `PROVER_KEYS_DIR` env var (see `main.rs`).
pub fn default_keys_dir() -> PathBuf {
    PathBuf::from("keys")
}
