// Copies the browser bundles of xterm.js from node_modules into public/.
const fs = require("fs");
const path = require("path");

const files = {
  "node_modules/@xterm/xterm/lib/xterm.js": "public/xterm.js",
  "node_modules/@xterm/xterm/css/xterm.css": "public/xterm.css",
  "node_modules/@xterm/addon-fit/lib/addon-fit.js": "public/addon-fit.js",
  "node_modules/@xterm/addon-web-links/lib/addon-web-links.js": "public/addon-web-links.js",
};

for (const [src, dest] of Object.entries(files)) {
  fs.copyFileSync(path.join(__dirname, src), path.join(__dirname, dest));
  console.log(`copied ${src} -> ${dest}`);
}

const licenses = ["@xterm/xterm", "@xterm/addon-fit", "@xterm/addon-web-links"]
  .map((name) => `${name}\n\n${fs.readFileSync(path.join(__dirname, "node_modules", name, "LICENSE"), "utf8")}`);
fs.writeFileSync(path.join(__dirname, "public/XTERM-LICENSE.txt"), licenses.join("\n\n"));
