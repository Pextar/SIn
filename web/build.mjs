// Build/serve the SIn signer PWA.
//
//   node build.mjs          one-shot build into dist/
//   node build.mjs --serve  build, then serve dist/ with live rebuilds
//
// We bundle the app entry (which pulls in nostr-tools) into a single
// dist/app.js, and copy the static app shell (html, css, manifest, service
// worker, icon) alongside it so the whole thing works offline.

import * as esbuild from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";

const outdir = "dist";
const serve = process.argv.includes("--serve");

const staticFiles = [
  "index.html",
  "styles.css",
  "manifest.webmanifest",
  "sw.js",
  "icon.svg",
];

async function copyStatic() {
  await Promise.all(staticFiles.map((f) => cp(`public/${f}`, `${outdir}/${f}`)));
}

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

const options = {
  entryPoints: ["src/app.js"],
  bundle: true,
  format: "esm",
  target: "es2022",
  outfile: `${outdir}/app.js`,
  sourcemap: true,
  minify: !serve,
};

if (serve) {
  const ctx = await esbuild.context(options);
  await ctx.rebuild();
  await copyStatic();
  // Rebuild app.js on change; static files are copied once at startup.
  await ctx.watch();
  const { host, port } = await ctx.serve({ servedir: outdir });
  console.log(`SIn signer dev server: http://${host}:${port}`);
} else {
  await esbuild.build(options);
  await copyStatic();
  console.log(`Built ${outdir}/ (app.js + ${staticFiles.length} static files)`);
}
