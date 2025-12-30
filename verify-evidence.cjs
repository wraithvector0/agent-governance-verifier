#!/usr/bin/env node
import fs from "fs";
import crypto from "crypto";

const file = process.argv[2];
if (!file) {
  console.error("Usage: ages-verify <evidence.json>");
  process.exit(1);
}

const evidence = JSON.parse(fs.readFileSync(file, "utf8"));

function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// 1. schema_version
if (evidence.schema_version !== "ages.evidence.v1") {
  console.log("TAMPERED");
  process.exit(0);
}

// 2. steps checks
const steps = evidence.steps;
for (let i = 0; i < steps.length; i++) {
  const step = structuredClone(steps[i]);

  if (step.schema_version !== "ages.v1") {
    console.log("TAMPERED");
    process.exit(0);
  }

  const expectedPrev =
    i === 0 ? null : steps[i - 1].chain.step_hash;

  if (step.chain.prev_step_hash !== expectedPrev) {
    console.log("TAMPERED");
    process.exit(0);
  }

  const providedHash = step.chain.step_hash;
  step.chain.step_hash = "";

  const canonical = JSON.stringify(step); // canonicalization assumed
  const computed = sha256Hex(Buffer.from(canonical, "utf8"));

  if (computed !== providedHash) {
    console.log("TAMPERED");
    process.exit(0);
  }
}

// 3. root hash
const lastHash = steps[steps.length - 1].chain.step_hash;
if (lastHash !== evidence.root_hash) {
  console.log("TAMPERED");
  process.exit(0);
}

console.log("VALID");
