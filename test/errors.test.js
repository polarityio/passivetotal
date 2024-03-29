const nock = require('nock');
const { doLookup, startup } = require('../integration');
const host = 'https://api.passivetotal.org';
const options = {
  host,
  user: 'test',
  apiKey: '12345',
  records: 10,
  enableRep: false,
  enablePairs: false,
  domainBlocklistRegex: '',
  ipBlocklistRegex: '',
  blocklist: '',
  maxConcurrent: 10,
  minTime: 1
};

const ip = {
  type: 'IPv4',
  value: '8.8.8.8',
  isPrivateIP: false,
  isIPv4: true
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
})

test('502 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(host).get(/.*/).reply(502);
  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const summary = lookupResults[0].data.details.summary;
    expect(summary.maxRequestQueueLimitHit).toBe(false);
    expect(summary.isConnectionReset).toBe(false);
    expect(summary.isGatewayTimeout).toBe(true);
    expect(summary.apiKeyLimitReached).toBe(false);
    done();
  });
});

test('504 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(host).get(/.*/).reply(504);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const summary = lookupResults[0].data.details.summary;
    expect(summary.maxRequestQueueLimitHit).toBe(false);
    expect(summary.isConnectionReset).toBe(false);
    expect(summary.isGatewayTimeout).toBe(true);
    expect(summary.apiKeyLimitReached).toBe(false);
    done();
  });
});

test('504 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(host).get(/.*/).reply(429);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const summary = lookupResults[0].data.details.summary;
    expect(summary.maxRequestQueueLimitHit).toBe(false);
    expect(summary.isConnectionReset).toBe(false);
    expect(summary.isGatewayTimeout).toBe(false);
    expect(summary.apiKeyLimitReached).toBe(true);
    done();
  });
});


test('500 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(host).get(/.*/).reply(500);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const summary = lookupResults[0].data.details.summary;
    expect(summary.maxRequestQueueLimitHit).toBe(false);
    expect(summary.isConnectionReset).toBe(false);
    expect(summary.isGatewayTimeout).toBe(true);
    expect(summary.apiKeyLimitReached).toBe(false);
    done();
  });
});

test('ECONNRESET response should result in `isConnectionReset`', (done) => {
  const scope = nock(host).get(/.*/).replyWithError({code: 'ECONNRESET'});
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const summary = lookupResults[0].data.details.summary;
    expect(summary.maxRequestQueueLimitHit).toBe(false);
    expect(summary.isConnectionReset).toBe(true);
    expect(summary.isGatewayTimeout).toBe(false);
    expect(summary.apiKeyLimitReached).toBe(false);
    done();
  });
});

test('400 response should return a normal integration error', (done) => {
  const scope = nock(host).get(/.*/).reply(400);
  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(err, null, 4));
    expect(err.length).toBe(1);
    expect(err[0].statusCode).toBe(400);
    done();
  });
});
