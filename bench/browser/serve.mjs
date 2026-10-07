// Static server for the browser bench: `node bench/browser/serve.mjs <dir>
// [port]` serves the directory build.mjs wrote. A page POSTs its log lines to
// /log (appended to <dir>/results.log) and its proofs to /proof (one JSON
// line each in <dir>/proofs.jsonl, for a reference verifier), so a phone's run
// is read on this host. Phones reach it through
// `adb reverse tcp:<port> tcp:<port>`.
import { createServer } from "node:http";
import { appendFile, readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";

const root = resolve(process.argv[2] ?? ".");
const port = Number(process.argv[3] ?? 18931);
const types = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".json": "application/json",
};

async function body(req) {
  let text = "";
  for await (const chunk of req) text += chunk;
  return text;
}

async function handle(req, res) {
  if (req.method === "POST" && req.url === "/proof") {
    const line = (await body(req)).replace(/\n/g, "");
    await appendFile(join(root, "proofs.jsonl"), line + "\n");
    res.writeHead(204).end();
    return;
  }
  if (req.method === "POST" && req.url === "/log") {
    const line = await body(req);
    await appendFile(
      join(root, "results.log"),
      `${new Date().toISOString()} ${line}\n`,
    );
    res.writeHead(204).end();
    return;
  }
  const path = normalize(
    decodeURIComponent(new URL(req.url, "http://x").pathname),
  );
  const file = join(root, path.endsWith("/") ? path + "index.html" : path);
  if (!file.startsWith(root)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const data = await readFile(file);
    res
      .writeHead(200, {
        "Content-Type": types[extname(file)] ?? "application/octet-stream",
        "Content-Length": data.length,
        "Cache-Control": "no-store",
      })
      .end(data);
  } catch {
    res.writeHead(404).end();
  }
}

// A client that drops mid-request (a closed tab) fails only its own request.
createServer((req, res) =>
  handle(req, res).catch((e) => {
    console.error(`${req.method} ${req.url}: ${e.message}`);
    if (!res.headersSent) res.writeHead(500);
    res.end();
  }),
).listen(port, "127.0.0.1", () => console.log(`serving ${root} on ${port}`));
