import assert from 'node:assert/strict';
import test from 'node:test';
import {run} from '../src/container-check.js';

test('--help prints usage and exits 0', () => {
  const log = console.log;
  const lines = [];
  console.log = (line) => lines.push(line);
  try {
    assert.equal(run(['--help']), 0);
    assert.equal(run(['scan', '-h']), 0);
  } finally {
    console.log = log;
  }
  assert.match(lines[0], /^Usage: container-check scan/);
});

test('missing arguments still exit 2', () => {
  const log = console.log;
  console.log = () => {};
  try {
    assert.equal(run([]), 2);
  } finally {
    console.log = log;
  }
});
