import test from 'node:test';
import assert from 'node:assert/strict';

// Recreate the minimal filtering logic from kubernetes-service-discovery.ts
// so this test can run under plain node without importing the .ts source.
const SERVICE_EXPOSURE_KINDS = new Set([
  'Service',
  'Ingress',
  'Gateway',
  'GatewayClass',
  'HTTPRoute',
  'GRPCRoute',
  'TCPRoute',
  'UDPRoute',
  'TLSRoute',
  'Route',
  'APIService',
  'ServiceExport',
  'ServiceImport',
  'VirtualService',
  'ServiceEntry',
  'DestinationRule',
  'DomainMapping',
  'ServerlessService'
]);

function classifyResource(resource, groupVersion) {
  const categories = new Set();
  const kind = String(resource?.kind || '');
  const name = String(resource?.name || '');
  const lower = `${groupVersion} ${kind} ${name}`.toLowerCase();

  if (groupVersion === 'v1' && (kind === 'Service' || name === 'services')) {
    categories.add('core-service');
  }
  if (kind === 'Endpoints' || kind === 'EndpointSlice' || /endpoint/.test(lower)) {
    categories.add('service-discovery-data');
  }
  if (['Ingress', 'Gateway', 'GatewayClass', 'HTTPRoute', 'GRPCRoute', 'TCPRoute', 'UDPRoute', 'TLSRoute', 'Route'].includes(kind)) {
    categories.add('traffic-entrypoint');
  }
  if (/serving\.knative\.dev/.test(lower) || ['DomainMapping', 'ServerlessService'].includes(kind)) {
    categories.add('serverless-serving');
  }
  if (/istio\.io/.test(lower) || ['VirtualService', 'ServiceEntry', 'DestinationRule'].includes(kind)) {
    categories.add('service-mesh');
  }
  if (kind === 'APIService' || kind === 'ServiceExport' || kind === 'ServiceImport') {
    categories.add('cluster-service-integration');
  }

  return Array.from(categories);
}

function isServiceLikeResource(resource, groupVersion) {
  const categories = classifyResource(resource, groupVersion);
  const kind = String(resource?.kind || '');
  const name = String(resource?.name || '');

  if (categories.length > 0) return true;
  if (SERVICE_EXPOSURE_KINDS.has(kind)) return true;

  const lowerCombined = `${kind} ${name} ${groupVersion}`.toLowerCase();
  if (/\b(service|services)\b/.test(lowerCombined)) return true;

  const singular = String(resource?.singularName || '').toLowerCase();
  if (singular === 'service') return true;

  const shortNames = Array.isArray(resource?.shortNames) ? resource.shortNames.map(s => String(s).toLowerCase()) : [];
  if (shortNames.includes('svc') || shortNames.includes('service') || shortNames.includes('services')) return true;

  return false;
}

// True positives
test('Service is recognized as service-like and classified as core-service', () => {
  const svc = { kind: 'Service', name: 'services' };
  assert.equal(isServiceLikeResource(svc, 'v1'), true);
  const cats = classifyResource(svc, 'v1');
  assert.equal(cats.includes('core-service'), true);
});

test('HTTPRoute is recognized as a traffic-entrypoint (service-like)', () => {
  const httpRoute = { kind: 'HTTPRoute', name: 'httproutes' };
  assert.equal(isServiceLikeResource(httpRoute, 'gateway.networking.k8s.io/v1beta1'), true);
  const cats = classifyResource(httpRoute, 'gateway.networking.k8s.io/v1beta1');
  assert.equal(cats.includes('traffic-entrypoint'), true);
});

// False positives that used to match on a naive substring should be excluded
test('ServiceAccount is NOT considered service-like', () => {
  const sa = { kind: 'ServiceAccount', name: 'serviceaccounts', singularName: 'serviceaccount', shortNames: ['sa'] };
  assert.equal(isServiceLikeResource(sa, 'v1'), false);
  assert.deepEqual(classifyResource(sa, 'v1'), []);
});

test('ServiceMonitor (prometheus) is NOT considered service-like by default', () => {
  const sm = { kind: 'ServiceMonitor', name: 'servicemonitors', singularName: 'servicemonitor', shortNames: ['sm'] };
  assert.equal(isServiceLikeResource(sm, 'monitoring.coreos.com/v1'), false);
  assert.deepEqual(classifyResource(sm, 'monitoring.coreos.com/v1'), []);
});

// Sanity check: shortNames containing "svc" still triggers a positive
test('A CRD advertising shortName "svc" is considered service-like via shortNames hint', () => {
  const crd = { kind: 'Thing', name: 'things', shortNames: ['svc'] };
  assert.equal(isServiceLikeResource(crd, 'example.com/v1'), true);
});
