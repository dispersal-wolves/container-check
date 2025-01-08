import assert from 'node:assert/strict';
import test from 'node:test';
import {auditCompose} from '../src/audit.js';

test('detects privileged host access and inline secrets', () => {
  const findings = auditCompose({services: {api: {
    image: 'example/api:latest',
    privileged: true,
    volumes: ['/var/run/docker.sock:/var/run/docker.sock'],
    ports: ['8080:8080'],
    environment: {API_TOKEN: 'plain-text'},
  }}});
  const rules = new Set(findings.map((item) => item.rule));
  for (const expected of ['privileged', 'docker-socket', 'public-port', 'unpinned-image', 'embedded-secret']) assert.equal(rules.has(expected), true);
});

test('a constrained service produces no findings', () => {
  const findings = auditCompose({services: {api: {
    image: 'example/api@sha256:abcdef',
    user: '1000:1000',
    read_only: true,
    healthcheck: {test: ['CMD', 'true']},
    ports: ['127.0.0.1:8080:8080'],
  }}});
  assert.deepEqual(findings, []);
});
