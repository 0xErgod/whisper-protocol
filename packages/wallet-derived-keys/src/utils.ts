export function normalizeAddress(addr: string): string {
  if (!addr) return addr;
  const lower = addr.toLowerCase();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
