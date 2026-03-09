#!/usr/bin/env node
// bin/run.mjs — called via `npx security-audit` or `npm run security:audit`

import { runAudit } from "../src/security-audit.mjs";

runAudit();
