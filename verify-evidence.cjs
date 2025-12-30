#!/usr/bin/env node
"use strict";

const fs = require("fs");
const crypto = require("crypto");

function fail() {
  console.log("TAMPERED");
  process.exit(0);
}

function ok() {
  console.log("VALID");
  process.exit(0);
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function main() {
  const file = process.argv[2];
  if (!file) fail();

  let evidence;
  try {
    evidence = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    fail();
  }

  if (evidence.schema_version !== "ages.evidence.v1") fail();
  if (!Array.isArray(evidence.steps) || evidence.steps.length === 0) fail();

  const steps = evidence.steps;

  for (let i = 0; i < steps.length; i++) {
    const step = structuredClone(steps[i]);

    if (step.schema_version !== "ages.v1") fail();
    if (step.step_index !== i) fail();

    const expectedPrev =
      i === 0 ? null : steps[i - 1].chain.step_hash;

    if (step.chain.prev_step_hash !== expectedPrev) fail();

    const provided = step.chain.step_hash;
    step.chain.step_hash = "";

    const canonical = JSON.stringify(step);
    const recomputed = sha256Hex(canonical);

    if (recomputed !== provided) fail();
  }

  const lastHash = steps[steps.length - 1].chain.step_hash;
  if (lastHash !== evidence.root_hash) fail();

  ok();
}

main();
