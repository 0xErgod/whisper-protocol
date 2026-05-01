import { SuiClient, SuiHTTPTransport } from "@mysten/sui/client";
import { SUI_RPC_URL } from "./config";

export const client = new SuiClient({
  transport: new SuiHTTPTransport({ url: SUI_RPC_URL }),
});
