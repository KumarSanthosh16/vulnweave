// Deliberately unsafe examples for validating a local Semgrep pack.
// Never copy these patterns into application code.

declare const app: { use: (middleware: unknown) => void };
declare function cors(): unknown;

app.use(cors());
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
