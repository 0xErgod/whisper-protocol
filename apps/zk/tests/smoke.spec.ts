import { expect, test } from "@playwright/test";

/**
 * End-to-end smoke: drive the rendered page through both
 * circuit panels' prove → verify → tamper cycles. Establishes
 * that the full Rust → WASM → TypeScript → browser chain
 * works exactly as a user would experience it.
 *
 * The prove path goes server-side (POST /prove/<id> to
 * prover-server); the verify path runs in-browser via the
 * loaded wasm bundle, exercising the same boundary the
 * standalone wasm-pack tests pin.
 *
 * Each panel's smoke spec follows three beats:
 *
 *   1. Click prove → wait for "proof produced" + timing
 *      readout (proves the HTTP path works).
 *   2. Click verify → wait for "✓ accepted" (proves the wasm
 *      verify path works against the freshly-fetched VK).
 *   3. Click verify (tampered) → wait for the rejection
 *      readout (proves the integrity property at the UI).
 */

test.describe("pedersen_opens_to panel", () => {
  test("prove + verify + tampered-verify", async ({ page }) => {
    await page.goto("/");

    // Wait for the panel to finish wasm init and become
    // interactive. The readout transitions from "initializing…"
    // to "ready. click prove." when the panel's setup runs.
    await expect(page.locator("#pedersen-readout")).toContainText(
      "ready. click prove.",
    );

    // 1. Prove.
    await page.locator("#pedersen-prove").click();
    await expect(page.locator("#pedersen-readout")).toContainText(
      "proof produced:",
      { timeout: 90_000 },
    );

    // 2. Verify.
    await page.locator("#pedersen-verify").click();
    await expect(page.locator("#pedersen-readout")).toContainText("✓ accepted");

    // 3. Tampered verify rejects.
    await page.locator("#pedersen-tamper").click();
    await expect(page.locator("#pedersen-readout")).toContainText(
      "tampered claim correctly rejected",
    );
  });
});

test.describe("envelope_open_at_0 panel", () => {
  test("prove + verify + tampered-verify", async ({ page }) => {
    await page.goto("/");

    await expect(page.locator("#envelope-readout")).toContainText(
      "ready. click prove.",
    );

    // 1. Prove. Envelope circuit's prove is slightly slower
    // than Pedersen's because of the envelope-side gadget
    // composition (ECDH + KDF + cipher + MAC).
    await page.locator("#envelope-prove").click();
    await expect(page.locator("#envelope-readout")).toContainText(
      "proof produced:",
      { timeout: 120_000 },
    );

    // 2. Verify.
    await page.locator("#envelope-verify").click();
    await expect(page.locator("#envelope-readout")).toContainText("✓ accepted");

    // 3. Tampered verify rejects.
    await page.locator("#envelope-tamper").click();
    await expect(page.locator("#envelope-readout")).toContainText(
      "tampered claim correctly rejected",
    );
  });
});

test("server URL renders in the header", async ({ page }) => {
  // Sanity check that the page loaded and the server URL
  // helper resolved. Cheap and orthogonal to the prove flows.
  await page.goto("/");
  await expect(page.locator("#server-url")).toContainText("127.0.0.1");
});
