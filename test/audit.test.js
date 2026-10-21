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

test('flags root users given with a group', () => {
  for (const user of ['0', 0, 'root', '0:0', 'root:root', 'ROOT:1000', '0:1000']) {
    const rules = auditCompose({services: {api: {user}}}).map((item) => item.rule);
    assert.equal(rules.includes('root-user'), true, `user ${user}`);
  }
  for (const user of ['1000', '1000:0', 'app:root']) {
    const rules = auditCompose({services: {api: {user}}}).map((item) => item.rule);
    assert.equal(rules.includes('root-user'), false, `user ${user}`);
  }
});

test('a registry port is not mistaken for an image tag', () => {
  const pinned = (image) => !auditCompose({services: {api: {image}}}).some((item) => item.rule === 'unpinned-image');
  assert.equal(pinned('registry.local:5000/team/api'), false);
  assert.equal(pinned('registry.local:5000/team/api:latest'), false);
  assert.equal(pinned('registry.local:5000/team/api:1.4.2'), true);
  assert.equal(pinned('registry.local:5000/team/api@sha256:abcdef'), true);
  assert.equal(pinned('api'), false);
  assert.equal(pinned('api:2.0'), true);
});
