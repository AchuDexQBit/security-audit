#!/usr/bin/env node

/**
 * Comprehensive Security Audit Tool
 *
 * Usage: node security-audit.mjs
 *
 * This script performs a thorough security audit of your Next.js project
 * and generates a detailed HTML report with findings and recommendations.
 */

import fs from "fs";
import path from "path";

// Configuration
const CONFIG = {
  projectRoot: process.cwd(),
  outputFile: "security-audit-report.html",
  excludeDirs: ["node_modules", ".next", "build", "dist", "out", ".git"],
  excludeFiles: ["security-audit.mjs", "security-audit-report.html"],
  fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".json", ".env"],
  assetsDirs: ["public/assets", "public", "assets", "src/assets"],
  assetsMaxBytes: 1 * 1024 * 1024, // 1MB
  publicApiRoutes: [],
};

// Security patterns to check
const SECURITY_PATTERNS = {
  hardcodedSecrets: [
    { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]{10,}['"]/gi, name: "API Key" },
    { pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, name: "Password" },
    { pattern: /secret\s*[:=]\s*['"][^'"]{10,}['"]/gi, name: "Secret" },
    { pattern: /token\s*[:=]\s*['"][^'"]{20,}['"]/gi, name: "Token" },
    {
      pattern: /private[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi,
      name: "Private Key",
    },
    {
      pattern: /aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['"][^'"]+['"]/gi,
      name: "AWS Access Key",
    },
    {
      pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi,
      name: "AWS Secret Key",
    },
    {
      pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/gi,
      name: "MongoDB Connection String",
    },
    {
      pattern: /postgres:\/\/[^:]+:[^@]+@/gi,
      name: "PostgreSQL Connection String",
    },
    { pattern: /mysql:\/\/[^:]+:[^@]+@/gi, name: "MySQL Connection String" },
    { pattern: /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/gi, name: "Bearer Token" },
    { pattern: /sk-[a-zA-Z0-9]{32,}/gi, name: "OpenAI API Key" },
  ],
  sqlInjection: [
    {
      // Only flag string concatenation when it's clearly inside a SQL call context
      pattern:
        /(?:query|sql|db\.|database\.|knex|sequelize|prisma\.\$queryRaw).*['"`]\s*\+\s*.*\s*\+\s*['"`]/gi,
      name: "SQL String Concatenation",
    },
    {
      pattern:
        /(?:query|sql|db\.|database\.|knex|sequelize|prisma\.\$queryRaw)\s*\(?\s*`[^`]*\$\{/gi,
      name: "Template Literal in SQL",
    },
    {
      pattern: /query\s*\(\s*['"`][^'"`]*\$\{/gi,
      name: "Unsanitized Query Parameter",
    },
    {
      pattern: /execSync\s*\(\s*['"`][^'"`]*\$\{/gi,
      name: "Command Injection Risk",
    },
  ],
  xssVulnerabilities: [
    { pattern: /dangerouslySetInnerHTML/gi, name: "dangerouslySetInnerHTML" },
    { pattern: /\.innerHTML\s*=/gi, name: "innerHTML Assignment" },
    { pattern: /document\.write\(/gi, name: "document.write()" },
    { pattern: /eval\s*\(/gi, name: "eval()" },
    { pattern: /new\s+Function\s*\(/gi, name: "Function Constructor" },
    { pattern: /setTimeout\s*\(\s*['"`]/gi, name: "setTimeout with String" },
    { pattern: /setInterval\s*\(\s*['"`]/gi, name: "setInterval with String" },
  ],
  insecurePatterns: [
    {
      pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/gi,
      name: "HTTP instead of HTTPS",
    },
    { pattern: /console\.log\(/gi, name: "Console.log (Info Disclosure)" },
    { pattern: /debugger;?/gi, name: "Debugger Statement" },
    { pattern: /TODO.*security/gi, name: "Security TODO Comment" },
    { pattern: /FIXME.*security/gi, name: "Security FIXME Comment" },
    {
      pattern: /localStorage\.setItem.*(?:token|password|secret)/gi,
      name: "Sensitive Data in LocalStorage",
    },
    {
      pattern: /sessionStorage\.setItem.*(?:token|password|secret)/gi,
      name: "Sensitive Data in SessionStorage",
    },
  ],
  weakCrypto: [
    {
      pattern: /crypto\.createHash\s*\(\s*['"]md5['"]/gi,
      name: "MD5 Hash (Weak)",
    },
    {
      pattern: /crypto\.createHash\s*\(\s*['"]sha1['"]/gi,
      name: "SHA1 Hash (Weak)",
    },
    {
      pattern: /Math\.random\(\).*(?:token|password|secret|key)/gi,
      name: "Math.random() for Security",
    },
  ],
};

// Results storage
const results = {
  critical: [],
  high: [],
  medium: [],
  low: [],
  info: [],
  summary: {
    filesScanned: 0,
    issuesFound: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
  },
};

// Utility function to recursively get all files
function getAllFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      if (!CONFIG.excludeDirs.includes(file)) {
        getAllFiles(filePath, fileList);
      }
    } else {
      // Check if file should be excluded
      const fileName = path.basename(filePath);
      if (CONFIG.excludeFiles.includes(fileName)) {
        return; // Skip this file
      }

      const ext = path.extname(file);
      if (CONFIG.fileExtensions.includes(ext) || file.startsWith(".env")) {
        fileList.push(filePath);
      }
    }
  });

  return fileList;
}

// Recursively compute total size of a directory
function getDirSize(dir) {
  let total = 0;
  try {
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        total += getDirSize(fullPath);
      } else {
        total += stat.size;
      }
    }
  } catch {
    // Directory doesn't exist or isn't readable — skip
  }
  return total;
}

// Add finding to results
function addFinding(
  severity,
  category,
  file,
  line,
  issue,
  recommendation,
  code = "",
) {
  const finding = {
    category,
    file: path.relative(CONFIG.projectRoot, file),
    line,
    issue,
    recommendation,
    code: code.trim().substring(0, 100),
  };

  results[severity].push(finding);
  results.summary[`${severity}Count`]++;
  // Don't count informational findings in the total
  if (severity !== "info") {
    results.summary.issuesFound++;
  }
}

// Check for hardcoded secrets
function checkHardcodedSecrets(file, content) {
  const lines = content.split("\n");

  SECURITY_PATTERNS.hardcodedSecrets.forEach(({ pattern, name }) => {
    const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        // Skip if it's a comment or example
        if (
          line.trim().startsWith("//") ||
          line.trim().startsWith("*") ||
          line.includes("example") ||
          line.includes("your-")
        ) {
          return;
        }

        addFinding(
          "critical",
          "Hardcoded Secrets",
          file,
          index + 1,
          `Potential ${name} hardcoded in source code`,
          `Move this credential to environment variables (.env file) and ensure .env is in .gitignore. Never commit secrets to version control.`,
          line,
        );
      }
    });
  });
}

// Check for SQL injection vulnerabilities
function checkSqlInjection(file, content) {
  const lines = content.split("\n");

  SECURITY_PATTERNS.sqlInjection.forEach(({ pattern, name }) => {
    const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        addFinding(
          "high",
          "SQL/Command Injection",
          file,
          index + 1,
          `Potential SQL/Command Injection: ${name}`,
          `Use parameterized queries or prepared statements. For ORMs like Prisma, use their safe query builders. Never concatenate user input into queries.`,
          line,
        );
      }
    });
  });
}

// Check for XSS vulnerabilities
function checkXss(file, content) {
  const lines = content.split("\n");

  SECURITY_PATTERNS.xssVulnerabilities.forEach(({ pattern, name }) => {
    const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        addFinding(
          "high",
          "XSS Vulnerability",
          file,
          index + 1,
          `Potential XSS vulnerability: ${name}`,
          `Avoid direct DOM manipulation. Use React's safe rendering or sanitize with DOMPurify. For dangerouslySetInnerHTML, ensure content is properly sanitized.`,
          line,
        );
      }
    });
  });
}

// Check for insecure patterns
function checkInsecurePatterns(file, content) {
  const lines = content.split("\n");

  SECURITY_PATTERNS.insecurePatterns.forEach(({ pattern, name }) => {
    const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        const severity =
          name.includes("TODO") || name.includes("FIXME")
            ? "info"
            : name.includes("Console.log")
              ? "low"
              : "medium";

        let recommendation = "";
        if (name.includes("HTTP")) {
          recommendation =
            "Always use HTTPS for external resources. HTTP is unencrypted and vulnerable to MITM attacks.";
        } else if (name.includes("Console.log")) {
          recommendation =
            "Remove console.log statements in production. They can leak sensitive information.";
        } else if (
          name.includes("LocalStorage") ||
          name.includes("SessionStorage")
        ) {
          recommendation =
            "Never store sensitive data in browser storage. Use secure, httpOnly cookies or server-side sessions.";
        } else if (name.includes("Debugger")) {
          recommendation =
            "Remove debugger statements before deploying to production.";
        } else {
          recommendation = "Review and address this security concern.";
        }

        addFinding(
          severity,
          "Insecure Pattern",
          file,
          index + 1,
          name,
          recommendation,
          line,
        );
      }
    });
  });
}

// Check for weak cryptography
function checkWeakCrypto(file, content) {
  const lines = content.split("\n");

  SECURITY_PATTERNS.weakCrypto.forEach(({ pattern, name }) => {
    const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        addFinding(
          "high",
          "Weak Cryptography",
          file,
          index + 1,
          name,
          `Use strong cryptographic algorithms. For hashing: bcrypt, argon2, or scrypt. For random values: crypto.randomBytes(). Avoid MD5, SHA1, and Math.random() for security purposes.`,
          line,
        );
      }
    });
  });
}

// Check .env files
function checkEnvFiles() {
  const envFiles = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
  ];

  envFiles.forEach((envFile) => {
    const envPath = path.join(CONFIG.projectRoot, envFile);

    if (fs.existsSync(envPath)) {
      addFinding(
        "info",
        "Environment Files",
        envPath,
        0,
        `Found ${envFile}`,
        `Ensure ${envFile} is in .gitignore and never committed to version control. Review all values for proper security.`,
        "",
      );
    }
  });
}

// Check .gitignore
function checkGitignore() {
  const gitignorePath = path.join(CONFIG.projectRoot, ".gitignore");

  if (!fs.existsSync(gitignorePath)) {
    addFinding(
      "high",
      "Missing Configuration",
      ".gitignore",
      0,
      "No .gitignore file found",
      "Create a .gitignore file to prevent committing sensitive files (.env, .env.local, etc.) to version control.",
      "",
    );
    return;
  }

  const gitignoreContent = fs.readFileSync(gitignorePath, "utf8");

  // Check if .env files are properly ignored
  // Accept .env*, .env.*, .env, .env.local, etc.
  const hasEnvIgnore = /\.env\*|\.env\.\*|\.env\.local|\.env$|^\.env$/m.test(
    gitignoreContent,
  );

  if (!hasEnvIgnore) {
    addFinding(
      "high",
      "Insecure Configuration",
      ".gitignore",
      0,
      "Missing .env file patterns in .gitignore",
      "Add .env* or specific .env patterns (.env, .env.local, .env.development, etc.) to .gitignore to prevent committing environment files with secrets.",
      "",
    );
  } else {
    // Add informational finding that .env files are properly ignored
    addFinding(
      "info",
      "Configuration",
      ".gitignore",
      0,
      "Environment files are properly ignored",
      "Good! Your .gitignore includes patterns to prevent committing .env files.",
      "",
    );
  }
}

// Check Next.js config for security headers
function checkNextConfig() {
  const configFiles = ["next.config.ts", "next.config.js", "next.config.mjs"];
  let configFound = false;

  configFiles.forEach((configFile) => {
    const configPath = path.join(CONFIG.projectRoot, configFile);

    if (fs.existsSync(configPath)) {
      configFound = true;
      const content = fs.readFileSync(configPath, "utf8");

      const securityHeaders = [
        "X-DNS-Prefetch-Control",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
      ];

      securityHeaders.forEach((header) => {
        if (!content.includes(header)) {
          addFinding(
            "medium",
            "Missing Security Headers",
            configPath,
            0,
            `Missing security header: ${header}`,
            `Add ${header} to your Next.js headers configuration to improve security. See: https://nextjs.org/docs/app/api-reference/next-config-js/headers`,
            "",
          );
        }
      });
    }
  });

  if (!configFound) {
    addFinding(
      "low",
      "Missing Configuration",
      "next.config.ts",
      0,
      "No Next.js config file found",
      "Create next.config.ts to add security headers and other security configurations.",
      "",
    );
  }
}

// Check API routes for authentication
function checkApiRoutes() {
  const apiDir = path.join(CONFIG.projectRoot, "app", "api");

  if (!fs.existsSync(apiDir)) {
    return;
  }

  const apiFiles = getAllFiles(apiDir);

  apiFiles.forEach((file) => {
    const relativeToApi = path.relative(apiDir, file).replace(/\\/g, "/");
    if (CONFIG.publicApiRoutes.includes(relativeToApi)) {
      return;
    }

    const content = fs.readFileSync(file, "utf8");
    const hasAuth = /auth|authenticate|verify|middleware|session|token/i.test(
      content,
    );

    if (
      !hasAuth &&
      (content.includes("export async function GET") ||
        content.includes("export async function POST") ||
        content.includes("export async function PUT") ||
        content.includes("export async function DELETE"))
    ) {
      addFinding(
        "high",
        "Missing Authentication",
        file,
        0,
        "API route may be missing authentication",
        "Implement authentication middleware or checks at the start of your API route handlers. Use NextAuth.js, JWT validation, or session verification.",
        "",
      );
    }
  });
}

// Check that the assets folder stays under the configured size limit
function checkAssetsSize() {
  let checkedAny = false;

  for (const relDir of CONFIG.assetsDirs) {
    const absDir = path.join(CONFIG.projectRoot, relDir);
    if (!fs.existsSync(absDir)) continue;

    checkedAny = true;
    const totalBytes = getDirSize(absDir);
    const totalKB = (totalBytes / 1024).toFixed(1);
    const limitKB = (CONFIG.assetsMaxBytes / 1024).toFixed(0);

    if (totalBytes > CONFIG.assetsMaxBytes) {
      addFinding(
        "high",
        "Assets Size",
        absDir,
        0,
        `Assets folder exceeds ${limitKB} KB limit (current: ${totalKB} KB)`,
        `Keep the assets folder under ${limitKB} KB to avoid slow page loads and large bundles. Compress images (use WebP/AVIF), remove unused files, or move large assets to a CDN.`,
        "",
      );
    } else {
      addFinding(
        "info",
        "Assets Size",
        absDir,
        0,
        `Assets folder is within the ${limitKB} KB limit (current: ${totalKB} KB)`,
        "Good! Assets folder size is acceptable.",
        "",
      );
    }

    // Only check the first matching directory
    break;
  }

  if (!checkedAny) {
    addFinding(
      "info",
      "Assets Size",
      path.join(CONFIG.projectRoot, "public/assets"),
      0,
      "No assets folder found — skipping size check",
      "If you add a public/assets directory, this audit will check that it stays under 1 MB.",
      "",
    );
  }
}

// Generate HTML report
function generateReport() {
  const now = new Date();
  const day = String(now.getDate()).padStart(2, "0");
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const year = now.getFullYear();
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");
  const formattedDate = `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 20px;
      line-height: 1.6;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      overflow: hidden;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      text-align: center;
    }
    .header h1 {
      font-size: 2.5em;
      margin-bottom: 10px;
      font-weight: 700;
    }
    .header p {
      opacity: 0.9;
      font-size: 1.1em;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 20px;
      padding: 40px;
      background: #f8f9fa;
    }
    .summary-card {
      background: white;
      padding: 20px;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      text-align: center;
    }
    .summary-card .number {
      font-size: 2.5em;
      font-weight: bold;
      margin-bottom: 5px;
    }
    .summary-card .label {
      color: #666;
      font-size: 0.9em;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .critical .number { color: #dc3545; }
    .high .number { color: #fd7e14; }
    .medium .number { color: #ffc107; }
    .low .number { color: #17a2b8; }
    .info .number { color: #6c757d; }
    .findings {
      padding: 40px;
    }
    .severity-section {
      margin-bottom: 40px;
    }
    .severity-header {
      display: flex;
      align-items: center;
      padding: 15px 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 1.3em;
      font-weight: 600;
      color: white;
    }
    .critical-header { background: #dc3545; }
    .high-header { background: #fd7e14; }
    .medium-header { background: #ffc107; color: #333; }
    .low-header { background: #17a2b8; }
    .info-header { background: #6c757d; }
    .finding {
      background: white;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 15px;
      transition: box-shadow 0.2s;
    }
    .finding:hover {
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: start;
      margin-bottom: 12px;
    }
    .finding-title {
      font-weight: 600;
      font-size: 1.1em;
      color: #333;
    }
    .finding-category {
      background: #e9ecef;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.85em;
      color: #495057;
    }
    .finding-location {
      color: #666;
      font-size: 0.9em;
      margin-bottom: 10px;
      font-family: 'Courier New', monospace;
    }
    .finding-recommendation {
      background: #f8f9fa;
      padding: 12px;
      border-radius: 6px;
      border-left: 4px solid #667eea;
      margin-top: 10px;
    }
    .finding-code {
      background: #272822;
      color: #f8f8f2;
      padding: 12px;
      border-radius: 6px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
      margin-top: 10px;
      overflow-x: auto;
    }
    .footer {
      background: #f8f9fa;
      padding: 30px;
      text-align: center;
      color: #666;
      border-top: 1px solid #e0e0e0;
    }
    .no-findings {
      text-align: center;
      padding: 40px;
      color: #666;
      font-size: 1.1em;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.8em;
      font-weight: 600;
      margin-left: 10px;
    }
    @media print {
      body { background: white; padding: 0; }
      .container { box-shadow: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Security Audit Report</h1>
      <p>Generated on ${formattedDate}</p>
      <p>Project: ${path.basename(CONFIG.projectRoot)}</p>
    </div>

    <div class="summary">
      <div class="summary-card critical">
        <div class="number">${results.summary.criticalCount}</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="number">${results.summary.highCount}</div>
        <div class="label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="number">${results.summary.mediumCount}</div>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="number">${results.summary.lowCount}</div>
        <div class="label">Low</div>
      </div>
    </div>

    <div class="findings">
      ${generateSeveritySection("critical", "Critical Issues", "")}
      ${generateSeveritySection("high", "High Severity Issues", "")}
      ${generateSeveritySection("medium", "Medium Severity Issues", "")}
      ${generateSeveritySection("low", "Low Severity Issues", "")}
    </div>

    <div class="footer">
      <p><strong>Files Scanned:</strong> ${
        results.summary.filesScanned
      } | <strong>Total Issues:</strong> ${
        results.summary.criticalCount +
        results.summary.highCount +
        results.summary.mediumCount +
        results.summary.lowCount
      }</p>
      <p style="margin-top: 10px;">This report was generated by an automated security audit tool.</p>
      <p>Review each finding carefully and implement recommended fixes.</p>
    </div>
  </div>
</body>
</html>
  `;

  return html;
}

function generateSeveritySection(severity, title, icon) {
  if (results[severity].length === 0) {
    return "";
  }

  const findings = results[severity]
    .map(
      (finding) => `
    <div class="finding">
      <div class="finding-header">
        <div class="finding-title">${finding.issue}</div>
        <div class="finding-category">${finding.category}</div>
      </div>
      <div class="finding-location">
        ${finding.file}${finding.line ? `:${finding.line}` : ""}
      </div>
      <div class="finding-recommendation">
        <strong>Recommendation:</strong> ${finding.recommendation}
      </div>
      ${
        finding.code
          ? `<div class="finding-code">${escapeHtml(finding.code)}</div>`
          : ""
      }
    </div>
  `,
    )
    .join("");

  return `
    <div class="severity-section">
      <div class="severity-header ${severity}-header">
        ${icon ? icon + " " : ""}${title}
        <span class="badge">${results[severity].length}</span>
      </div>
      ${findings}
    </div>
  `;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Main execution
function runAudit() {
  console.log("Starting security audit...\n");

  const startTime = Date.now();

  // Get all files to scan
  console.log("Scanning project files...");
  const files = getAllFiles(CONFIG.projectRoot);
  results.summary.filesScanned = files.length;
  console.log(`   Found ${files.length} files to analyze\n`);

  // Run checks
  console.log("Checking for hardcoded secrets...");
  console.log("Checking for injection vulnerabilities...");
  console.log("Checking for XSS vulnerabilities...");
  console.log("Checking for insecure patterns...");
  console.log("Checking for weak cryptography...");

  files.forEach((file) => {
    try {
      const content = fs.readFileSync(file, "utf8");

      checkHardcodedSecrets(file, content);
      checkSqlInjection(file, content);
      checkXss(file, content);
      checkInsecurePatterns(file, content);
      checkWeakCrypto(file, content);
    } catch (error) {
      // Skip files that can't be read
    }
  });

  console.log("Checking environment files...");
  checkEnvFiles();

  console.log("Checking .gitignore...");
  checkGitignore();

  console.log("Checking Next.js configuration...");
  checkNextConfig();

  console.log("Checking API routes...");
  checkApiRoutes();

  console.log("Checking assets folder size...");
  checkAssetsSize();

  // Generate report
  console.log("\nGenerating report...");
  const html = generateReport();
  const outputPath = path.join(CONFIG.projectRoot, CONFIG.outputFile);
  fs.writeFileSync(outputPath, html);

  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);

  console.log("\nSecurity audit complete!\n");
  console.log("═══════════════════════════════════════");
  console.log(`Summary:`);
  console.log(`   Files Scanned: ${results.summary.filesScanned}`);
  console.log(`   Critical:   ${results.summary.criticalCount}`);
  console.log(`   High:       ${results.summary.highCount}`);
  console.log(`   Medium:     ${results.summary.mediumCount}`);
  console.log(`   Low:        ${results.summary.lowCount}`);
  console.log(`   Duration:   ${duration}s`);
  console.log("═══════════════════════════════════════");
  console.log(`\nReport saved to: ${CONFIG.outputFile}`);
  console.log(`   Open it in your browser to view detailed findings.\n`);

  if (
    results.summary.criticalCount > 0 ||
    results.summary.highCount > 0 ||
    results.summary.mediumCount > 0
  ) {
    console.error("Security issues found");
    process.exit(1);
  }
}

export { runAudit };
