const SECRET_NAME = /(password|passwd|secret|token|api[_-]?key|private[_-]?key)/i;
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'DAC_READ_SEARCH']);

function finding(service, rule, severity, message) {
  return {service, rule, severity, message};
}

function normalizeEnvironment(environment) {
  if (Array.isArray(environment)) return Object.fromEntries(environment.map((item) => item.split('=', 2)));
  return environment ?? {};
}

function normalizeVolumes(volumes) {
  return (volumes ?? []).map((volume) => typeof volume === 'string' ? volume : `${volume.source ?? ''}:${volume.target ?? ''}:${volume.read_only ? 'ro' : 'rw'}`);
}

function normalizePorts(ports) {
  return (ports ?? []).map((port) => typeof port === 'string' || typeof port === 'number' ? String(port) : `${port.host_ip ?? ''}:${port.published ?? ''}:${port.target ?? ''}/${port.protocol ?? 'tcp'}`);
}

export function auditService(name, service) {
  const findings = [];
  if (service.privileged === true) findings.push(finding(name, 'privileged', 'critical', 'Privileged mode grants broad host access.'));
  for (const key of ['network_mode', 'pid', 'ipc']) {
    if (service[key] === 'host') findings.push(finding(name, `host-${key}`, 'high', `${key} shares the host namespace.`));
  }
  for (const capability of service.cap_add ?? []) {
    if (DANGEROUS_CAPS.has(String(capability).toUpperCase())) findings.push(finding(name, 'dangerous-capability', 'high', `Capability ${capability} is unusually powerful.`));
  }
  for (const volume of normalizeVolumes(service.volumes)) {
    if (/docker\.sock/i.test(volume)) findings.push(finding(name, 'docker-socket', 'critical', 'Docker socket access can control the host daemon.'));
    if (/^(\/|[A-Za-z]:\\?):\/?[^:]*(:rw)?$/.test(volume)) findings.push(finding(name, 'host-root-mount', 'critical', 'Host root appears to be mounted into the container.'));
    else if (/^(\/|[A-Za-z]:\\)/.test(volume) && !volume.endsWith(':ro')) findings.push(finding(name, 'writable-bind-mount', 'medium', `Writable host bind mount: ${volume}`));
  }
  for (const port of normalizePorts(service.ports)) {
    if (!port.startsWith('127.0.0.1:') && !port.startsWith('[::1]:')) findings.push(finding(name, 'public-port', 'medium', `Published port may bind all interfaces: ${port}`));
  }
  const image = String(service.image ?? '');
  if (image && (!image.includes('@sha256:') && (!image.includes(':') || image.endsWith(':latest')))) findings.push(finding(name, 'unpinned-image', 'medium', `Image is not pinned to a digest or immutable version: ${image}`));
  if (service.read_only !== true) findings.push(finding(name, 'writable-rootfs', 'low', 'Container root filesystem is writable.'));
  if (!service.healthcheck || service.healthcheck.disable === true) findings.push(finding(name, 'missing-healthcheck', 'low', 'No active container health check is defined.'));
  if (service.user === undefined || String(service.user) === '0' || String(service.user).toLowerCase() === 'root') findings.push(finding(name, 'root-user', 'medium', 'Container may run as root.'));
  for (const [key, value] of Object.entries(normalizeEnvironment(service.environment))) {
    if (SECRET_NAME.test(key) && value !== null && value !== undefined && String(value).trim() !== '') findings.push(finding(name, 'embedded-secret', 'high', `Sensitive-looking environment variable ${key} has an inline value.`));
  }
  return findings;
}

export function auditCompose(compose) {
  const services = compose.services ?? {};
  return Object.entries(services).flatMap(([name, service]) => auditService(name, service));
}
