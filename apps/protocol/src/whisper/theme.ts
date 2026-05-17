import type { ThemeVars } from "@mysten/dapp-kit";

// Bind dApp Kit's theme contract to our token system. The values below
// reference the same colors as styles/tokens.css so wallet UI feels
// continuous with the rest of the app.
//
// dApp Kit's primary button is the connect/connected pill in the bar;
// the outline button is the "Disconnect" item in the dropdown.
const TEXT = "#eeeeee";
const TEXT_DIM = "#a8a8a8";
const TEXT_FAINT = "#6c6c6c";
const BORDER = "#3a3a3a";
const BORDER_STRONG = "#6c6c6c";
const BG_ELEVATED = "#1c1c1c";
const BG_BUBBLE = "#262626";
const BG = "#080808";
const BRAND = "#ff9944";
const BRAND_FAINT = "rgba(255, 153, 68, 0.12)";
const BAD = "#ff5555";

export const whisperTheme: ThemeVars = {
  blurs: {
    modalOverlay: "blur(2px)",
  },
  backgroundColors: {
    primaryButton: BRAND,
    primaryButtonHover: BRAND,
    outlineButtonHover: BRAND_FAINT,
    walletItemHover: BG_BUBBLE,
    walletItemSelected: BRAND_FAINT,
    modalOverlay: "rgba(0, 0, 0, 0.65)",
    modalPrimary: BG_ELEVATED,
    modalSecondary: BG,
    iconButton: "transparent",
    iconButtonHover: BG_BUBBLE,
    dropdownMenu: BG_ELEVATED,
    dropdownMenuSeparator: BORDER,
  },
  borderColors: {
    outlineButton: BORDER_STRONG,
  },
  colors: {
    primaryButton: "#080808",
    outlineButton: TEXT,
    body: TEXT,
    bodyMuted: TEXT_DIM,
    bodyDanger: BAD,
    iconButton: TEXT_FAINT,
  },
  radii: {
    small: "0",
    medium: "0",
    large: "0",
    xlarge: "0",
  },
  shadows: {
    primaryButton: "none",
    walletItemSelected: "none",
  },
  fontWeights: {
    normal: "400",
    medium: "400",
    bold: "400",
  },
  fontSizes: {
    small: "0.78rem",
    medium: "0.85rem",
    large: "0.95rem",
    xlarge: "1.05rem",
  },
  typography: {
    fontFamily:
      '"Geist Mono", "GeistMono-Regular", "JetBrains Mono", Consolas, Monaco, monospace',
    fontStyle: "normal",
    lineHeight: "1.3",
    letterSpacing: "0.05ch",
  },
};
