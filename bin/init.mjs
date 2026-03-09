#!/usr/bin/env node
// bin/init.mjs - called via `npx security-audit-init`
// Copies the bundled GitHub Actions workflow into the consumer project.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const srcWorkflow = path.resolve(
  __dirname,
  "../workflows/security-gate-caller.yml",
);
const destDir = path.resolve(process.cwd(), ".github", "workflows");
const destWorkflow = path.join(destDir, "security-gate.yml");

console.log("\n@AchuDexQBit/security-audit - init\n");

// 1. Create .github/workflows if it doesn't exist
if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
  console.log("Created .github/workflows/");
}

// 2. Warn if already exists
if (fs.existsSync(destWorkflow)) {
  console.log(".github/workflows/security-gate.yml already exists.");
  console.log("Delete it first if you want to re-initialise.\n");
  process.exit(0);
}

// 3. Copy workflow
fs.copyFileSync(srcWorkflow, destWorkflow);
console.log("Copied security-gate.yml → .github/workflows/security-gate.yml");

// 4. Add .npmrc reminder
const npmrcPath = path.resolve(process.cwd(), ".npmrc");
if (!fs.existsSync(npmrcPath)) {
  console.log(
    "\nNo .npmrc found. To authenticate with GitHub Packages, create one:",
  );
  console.log("@AchuDexQBit:registry=https://npm.pkg.github.com");
  console.log("//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n");
} else {
  const npmrc = fs.readFileSync(npmrcPath, "utf8");
  if (!npmrc.includes("npm.pkg.github.com")) {
    console.log("\nYour .npmrc may not be configured for GitHub Packages.");
    console.log("Add these lines to .npmrc:");
    console.log("@AchuDexQBit:registry=https://npm.pkg.github.com");
    console.log("//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n");
  }
}

// 5. Remind about package.json scripts
console.log("\n📋 Add these scripts to your project's package.json:");
console.log(
  `"security:audit": "node node_modules/@AchuDexQBit/security-audit/bin/run.mjs",`,
);
console.log(
  `"security:init":  "node node_modules/@AchuDexQBit/security-audit/bin/init.mjs",`,
);
console.log(`"npm-audit":      "npm audit --audit-level=high"\n`);

console.log("Done! Commit .github/workflows/security-gate.yml to your repo.\n");
