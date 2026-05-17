/**
 * HTTP client for the running prover-server.
 *
 * Three operations per circuit, matching `crates/prover-server`'s
 * routes:
 *
 *   POST /prove/<id>   body: Inputs JSON, returns proof bytes
 *   GET  /vk/<id>      returns VK bytes
 *   POST /verify/<id>  body: {public_inputs, proof_hex}, returns {accepted}
 *
 * The page uses /prove and /vk in normal flow. /verify is also
 * exposed but the page deliberately does verification locally via
 * `prover-wasm` instead — that exercises the wasm boundary and
 * matches the on-chain pattern (verifier doesn't trust the
 * prover-server, it just consumes the proof + VK).
 */

const DEFAULT_SERVER = "http://127.0.0.1:3001";

export function serverUrl(): string {
  // Vite exposes import.meta.env.* at build time; the override is
  // useful for deploying the page against a non-default server.
  const fromEnv = (import.meta as { env?: Record<string, string> }).env
    ?.VITE_PROVER_SERVER;
  return fromEnv ?? DEFAULT_SERVER;
}

/**
 * POST a JSON `Inputs` body to `/prove/<circuit>`. Returns the
 * proof bytes as a `Uint8Array`. Throws on non-2xx with the
 * server's error message.
 */
export async function postProve(
  circuit: string,
  inputs: unknown,
): Promise<Uint8Array> {
  const url = `${serverUrl()}/prove/${circuit}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(inputs),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`/prove/${circuit} ${resp.status}: ${text}`);
  }
  const bytes = await resp.arrayBuffer();
  return new Uint8Array(bytes);
}

/**
 * GET `/vk/<circuit>` and return the VK bytes. Throws on non-2xx.
 */
export async function getVk(circuit: string): Promise<Uint8Array> {
  const url = `${serverUrl()}/vk/${circuit}`;
  const resp = await fetch(url);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`/vk/${circuit} ${resp.status}: ${text}`);
  }
  const bytes = await resp.arrayBuffer();
  return new Uint8Array(bytes);
}
