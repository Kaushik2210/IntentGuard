// Copies the static export (out/) into ../docs so GitHub Pages can serve it from branch master, folder /docs.
// Only the site's own files are replaced; the markdown and spreadsheets already in docs/ are left alone.
import { cpSync, existsSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "out");
const docs = join(here, "..", "..", "docs");
if (!existsSync(out)) throw new Error("run `next build` first: out/ does not exist");

for (const name of ["_next", "index.html", "404.html", "404", "index.txt", "__next.__PAGE__.txt", "__next._full.txt", "__next._head.txt", "__next._index.txt", "__next._tree.txt", "_not-found"]) {
  rmSync(join(docs, name), { recursive: true, force: true });
}
cpSync(out, docs, { recursive: true });
writeFileSync(join(docs, ".nojekyll"), "");
console.log("published", readdirSync(out).join(", "), "->", docs);
