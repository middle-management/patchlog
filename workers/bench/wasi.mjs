// Runs the CPU benchmark built for wasm32-wasip1 under Node's WASI, i.e. on
// V8, the engine workerd runs Workers on.
//   cargo build --release -p patchlog-bench --target wasm32-wasip1 && node bench/wasi.mjs
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const wasi = new WASI({ version: "preview1", args: ["bench"], env: {} });
const wasm = await WebAssembly.compile(await readFile(new URL("../target/wasm32-wasip1/release/patchlog-bench.wasm", import.meta.url)));
const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
wasi.start(instance);
