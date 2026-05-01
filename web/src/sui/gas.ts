import type { GasInfo } from "./queries";

const MIST_PER_SUI = 1_000_000_000n;

export function formatMist(mist: bigint): string {
  // Show MIST for tiny values, SUI for everything that would round to a useful 4-decimal value.
  const abs = mist < 0n ? -mist : mist;
  if (abs < 100_000n) {
    return `${mist.toString()} MIST`;
  }
  // Format as SUI with up to 6 decimals, trimming trailing zeros.
  const negative = mist < 0n;
  const v = negative ? -mist : mist;
  const whole = v / MIST_PER_SUI;
  const frac = v % MIST_PER_SUI;
  const fracStr = frac.toString().padStart(9, "0").slice(0, 6).replace(/0+$/, "");
  const body = fracStr.length === 0 ? whole.toString() : `${whole.toString()}.${fracStr}`;
  return `${negative ? "-" : ""}${body} SUI`;
}

export function shortGas(gas: GasInfo | null): string {
  if (!gas) return "—";
  return formatMist(gas.netMist);
}

export function gasBreakdownTooltip(gas: GasInfo | null): string {
  if (!gas) return "gas data unavailable";
  return [
    `computation ${formatMist(gas.computationMist)}`,
    `storage ${formatMist(gas.storageMist)}`,
    `rebate -${formatMist(gas.rebateMist)}`,
    `net ${formatMist(gas.netMist)}`,
  ].join("\n");
}
