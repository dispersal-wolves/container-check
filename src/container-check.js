#!/usr/bin/env node
import childProcess from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {auditCompose} from './audit.js';

function usage() {
  console.log('Usage: container-check scan <compose.yaml|compose.json> [--format text|json] [--strict low|medium|high|critical]');
}

function loadCompose(file) {
  if (path.extname(file).toLowerCase() === '.json') return JSON.parse(fs.readFileSync(file, 'utf8'));
  const result = childProcess.spawnSync('docker', ['compose', '-f', file, 'config', '--format', 'json'], {encoding: 'utf8'});
  if (result.error) throw new Error(`Docker Compose is required to normalize YAML: ${result.error.message}`);
  if (result.status !== 0) throw new Error(result.stderr.trim() || 'Docker Compose could not normalize the file.');
  return JSON.parse(result.stdout);
}

export function run(argv) {
  if (argv[0] !== 'scan' || !argv[1]) {
    usage();
    return 2;
  }
  const file = path.resolve(argv[1]);
  if (!fs.existsSync(file)) {
    console.error(`Compose file not found: ${file}`);
    return 2;
  }
  const formatIndex = argv.indexOf('--format');
  const format = formatIndex >= 0 ? argv[formatIndex + 1] : 'text';
  const strictIndex = argv.indexOf('--strict');
  const strict = strictIndex >= 0 ? argv[strictIndex + 1] : null;
  const levels = ['low', 'medium', 'high', 'critical'];
  if (!['text', 'json'].includes(format) || (strict && !levels.includes(strict))) {
    console.error('Invalid --format or --strict value.');
    return 2;
  }
  try {
    const compose = loadCompose(file);
    const findings = auditCompose(compose);
    const summary = Object.fromEntries(levels.map((level) => [level, findings.filter((item) => item.severity === level).length]));
    if (format === 'json') console.log(JSON.stringify({schema: 'dispersal-wolves/container-check/v1', summary, findings}, null, 2));
    else {
      for (const item of findings) console.log(`[${item.severity.toUpperCase()}] ${item.service} · ${item.rule}: ${item.message}`);
      console.log(`${Object.keys(compose.services ?? {}).length} services · ${findings.length} findings`);
    }
    return strict && findings.some((item) => levels.indexOf(item.severity) >= levels.indexOf(strict)) ? 1 : 0;
  } catch (error) {
    console.error(`Container Check: ${error.message}`);
    return 2;
  }
}

if (process.argv[1]?.endsWith('container-check.js')) process.exitCode = run(process.argv.slice(2));
