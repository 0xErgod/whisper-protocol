import type { Transaction } from "@mysten/sui/transactions";

export type DemoMode = "wallet" | "dev";

export interface ActiveAccount {
  address: string;
  source: DemoMode;
  label?: string;
}

export interface TxExecutionResult {
  digest: string;
}

export type TxExecutor = (transaction: Transaction) => Promise<TxExecutionResult>;
