'use strict';

const request = require('request');
const _ = require('lodash');
const {
  flow,
  get,
  getOr,
  slice,
  orderBy,
  filter,
  includes,
  __,
  flatMap,
  find,
  map,
  toLower,
  concat,
  uniqWith,
  isEqual
} = require('lodash/fp');
const Bottleneck = require('bottleneck');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

const NodeCache = require('node-cache');

const articlesCache = new NodeCache({
  stdTTL: 5 * 60
});

let Logger;
let limiter = null;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_ENTITY_LENGTH = 100;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);
const INDICATOR_TYPES = {
  domain: ['url', 'domain', 'domain_port'],
  IPv4: ['ip_port', 'ip']
};

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10),
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10)
  });
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function _limiterLookup(entity, options, cb) {
  if (entity.type === 'custom') {
    doDetailsLookup(
      { path: '/v2/trackers/search', qs: { query: entity.value, type: 'GoogleAnalyticsTrackingId' } },
      entity,
      options,
      cb
    );
  } else {
    doDetailsLookup({ path: '/v2/cards/summary', qs: { query: entity.value } }, entity, options, cb);
  }
}

function createLookupResultObject(result) {
  if (
    !result.body ||
    (get('entity.type', result) !== 'custom' &&
      get('body.data_summary.resolutions.count', result) === 0 &&
      get('body.data_summary.certificates.count', result) === 0 &&
      get('body.data_summary.hashes.count', result) === 0 &&
      get('body.data_summary.projects.count', result) === 0 &&
      get('body.data_summary.articles.count', result) === 0 &&
      get('body.data_summary.trackers.count', result) === 0 &&
      get('body.data_summary.components.count', result) === 0 &&
      get('body.data_summary.host_pairs.count', result) === 0 &&
      get('body.data_summary.cookies.count', result) === 0)
  ) {
    return {
      entity: result.entity,
      data: null
    };
  } else if (result.entity.type != 'custom') {
    return {
      entity: result.entity,
      data: {
        summary: [
          'Resolutions: ' +
            get('body.data_summary.resolutions.count', result) +
            ', Articles: ' +
            get('body.data_summary.articles.count', result) +
            ', Certs: ' +
            get('body.data_summary.certificates.count', result) +
            ', Hashes: ' +
            get('body.data_summary.hashes.count', result) +
            ', Host Pairs: ' +
            get('body.data_summary.host_pairs.count', result) +
            ', Projects: ' +
            get('body.data_summary.projects.count', result) +
            ', Trackers: ' +
            get('body.data_summary.trackers.count', result) +
            ', Components: ' +
            get('body.data_summary.components.count', result)
        ],
        details: {
          summary: result.body
        }
      }
    };
  } else {
    result.body.results = flow(get('body.results'), slice(0, options.records))(result);

    // Mutation of tracker
    result.body.results.forEach((tracker) => {
      tracker = Object.keys(tracker).length > 0;
    });

    return {
      entity: result.entity,
      data: {
        summary: ['Trackers:' + result.body.results.length],
        details: {
          tracker: result.body.results
        }
      }
    };
  }
}

function doLookup(entities, options, cb) {
  const lookupResults = [];
  const errors = [];

  let hasValidIndicator = false;
  let numConnectionResets = 0;
  let numThrottled = 0;
  let numApiKeyLimitedReached = 0;

  _setupRegexBlocklists(options);

  if (limiter === null) {
    _setupLimiter(options);
  }

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      hasValidIndicator = true;
      Logger.info('Looking up indicator ' + entity.value);
      limiter.submit(_limiterLookup, entity, options, (err, result) => {
        const searchLimitObject = reachedSearchLimit(err, result);
        if (searchLimitObject) {
          // Tracking for logging purposes
          if (searchLimitObject.isConnectionReset || searchLimitObject.isGatewayTimeout) numConnectionResets++;
          if (searchLimitObject.maxRequestQueueLimitHit) numThrottled++;
          if (searchLimitObject.apiKeyLimitReached) numApiKeyLimitedReached++;

          lookupResults.push({
            entity,
            isVolatile: true, // prevent limit reached results from being cached
            data: {
              summary: ['Search limit reached'],
              details: {
                summary: searchLimitObject
              }
            }
          });
        } else if (err) {
          // a regular error occurred that is not a search limit related error
          errors.push(err);
        } else {
          // no search limit error and no regular error so create a normal lookup object
          const lookupResultObject = createLookupResultObject(result);
          Logger.trace({ lookupResultObject }, 'lookupResultObject');
          lookupResults.push(lookupResultObject);
        }

        // Check if we got all our results back from the limiter
        if (lookupResults.length + errors.length === entities.length) {
          if (numConnectionResets > 0 || numThrottled > 0) {
            Logger.warn(
              {
                numEntitiesLookedUp: entities.length,
                numConnectionResets: numConnectionResets,
                numLookupsThrottled: numThrottled,
                numApiKeyLimitedReached
              },
              'Lookup Limit Reached'
            );
          }

          if (errors.length > 0) {
            cb(errors);
          } else {
            cb(null, lookupResults);
          }
        }
      });
    }
  });
}

function doDetailsLookup(request, entity, options, cb) {
  let requestOptions = {
    method: 'GET',
    uri: `${options.host}${request.path}`,
    auth: {
      user: options.user,
      pass: options.apiKey
    },
    qs: request.qs,
    json: true
  };

  Logger.trace({ requestOptions }, 'Looking at the Request');

  requestWithDefaults(requestOptions, (error, response, body) => {
    let processedResult = handleRestError(error, entity, response, body);

    if (processedResult.error) {
      cb(processedResult.error);
      return;
    }
    //Logger.trace({ processedResult }, 'Looking at the Result');
    cb(null, processedResult);
  });
}

function reachedSearchLimit(err, result) {
  const maxRequestQueueLimitHit =
    (_.isEmpty(err) && _.isEmpty(result)) || (err && err.message === 'This job has been dropped by Bottleneck');

  let statusCode = _.get(err, 'statusCode', 0);
  //statusCode = 429;
  const isGatewayTimeout = statusCode === 502 || statusCode === 504;
  const apiKeyLimitReached = statusCode === 429;
  const isConnectionReset = _.get(err, 'code', '') === 'ECONNRESET';

  if (maxRequestQueueLimitHit || isConnectionReset || isGatewayTimeout || apiKeyLimitReached) {
    return {
      maxRequestQueueLimitHit,
      isConnectionReset,
      isGatewayTimeout,
      apiKeyLimitReached
    };
  }

  return null;
}

// function onDetails(lookupObject, options, cb) {
//   let entity = lookupObject.entity;
//   if (entity.type === 'domain' || entity.type === 'IPv4') {
//     const articles = articlesCache.get('articles');
//     async.parallel(
//       {
//         whois: doDetailsLookup({ path: '/v2/whois', qs: { query: entity.value } }, entity, options), // fast 112 ms
//         pdns: doDetailsLookup({ path: '/v2/dns/passive', qs: { query: entity.value } }, entity, options), // fast 3.3 seconds
//         malware: doDetailsLookup({ path: '/v2/enrichment/malware', qs: { query: entity.value } }, entity, options), // fast 282 ms
//         certificates: doDetailsLookup(
//           {
//             path: '/v2/ssl-certificate/search', // 4.41 seconds
//             qs: { query: entity.value, field: 'subjectCommonName' }
//           },
//           entity,
//           options
//         ),
//         ...(!articles
//           ? {
//               articles: doDetailsLookup({ path: '/v2/articles', qs: { sort: 'indicators' } }, entity, options) // fast 156ms
//             }
//           : { articles: (done) => done(null, articles) }),
//         ...(options.enableRep && {
//           reputation: doDetailsLookup({ path: '/v2/reputation', qs: { query: entity.value } }, entity, options)
//         }),
//         ...(options.enablePairs && {
//           parentPairs: doDetailsLookup(
//             { path: '/v2/host-attributes/pairs', qs: { query: entity.value, direction: 'parents' } },
//             entity,
//             options
//           ),
//           childPairs: doDetailsLookup(
//             { path: '/v2/host-attributes/pairs', qs: { query: entity.value, direction: 'children' } },
//             entity,
//             options
//           )
//         })
//       },
//       (err, { whois, pdns, certificates, malware, reputation, parentPairs, childPairs, articles }) => {
//         if (err) return cb(err);
//
//         if (articles) articlesCache.set('articles', articles);
//
//         lookupObject.data.details = {
//           summary: lookupObject.data.details,
//           whois: getBody(whois),
//           pdns: orderBy('lastSeen', 'asc', getRecords(options.records, pdns)),
//           certificates: getRecords(options.records, certificates),
//           malware: getRecords(options.records, malware),
//           reputation: getBody(reputation),
//           pairs: flow(
//             concat(getRecords(options.records, parentPairs)),
//             uniqWith(isEqual)
//           )(getRecords(options.records, childPairs)),
//           articles: searchArticles(entity, articles)
//         };
//
//         Logger.trace({ lookup: lookupObject.data }, 'Looking at the data after on details.');
//
//         cb(null, lookupObject.data);
//       }
//     );
//   } else {
//     cb(null, lookupObject.data);
//   }
// }

const getBody = getOr([], 'body');
const getRecords = (recordsCount, result) => flow(get('body.results'), slice(0, recordsCount))(result);
const getArticles = (recordsCount, result) => {

  const articles = _.get(result, 'body.articles', []);
  Logger.info({result, articles}, 'getArticles');
  if (Array.isArray(articles)) {
    return articles.slice(0, recordsCount);
  } else {
    return [];
  }
};

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    Logger.error('we got an error');
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200 && body) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 401) {
    result = {
      error: {
        detail: 'Invalid credentials'
      }
    };
  } else if (res.statusCode === 402) {
    result = {
      error: {
        detail: 'Quota Exceeded',
        msg: body.message
      }
    };
  } else {
    // unexpected status code
    result = {
      error: {
        detail: 'Unexpected HTTP Status Received',
        statusCode: res ? res.statusCode : 'Not Available',
        message: body ? body.message : 'Not Available',
        body: body
      }
    };
  }

  return result;
}

function _isInvalidEntity(entity) {
  // Domains should not be over 100 characters long so if we get any of those we don't look them up
  if (entity.value.length > MAX_ENTITY_LENGTH) {
    return true;
  }

  // Domain labels (the parts in between the periods, must be 63 characters or less
  if (entity.isDomain) {
    const invalidLabel = entity.value.split('.').find((label) => {
      return label.length > MAX_DOMAIN_LABEL_LENGTH;
    });

    if (typeof invalidLabel !== 'undefined') {
      return true;
    }
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

/**
 * This is a helper function that wraps the onMessage searches with the required logic to detect search limit lookups
 *
 * @param err An error (if any) from the onMessage search lookup
 * @param data The result of the onMessage search lookup
 * @param getDataHandler a function that gets invoked if there was no error or search limit reached.  The function
 * should take the resulting data and process it.  This is customized per data type as each data type needs to be
 * handled in a slightly different manner.
 * @param cb The onMessage callback to execute with the return data
 * @returns {*}
 */
function onMessageResultHandler(err, data, getDataHandler, options, cb) {
  const searchLimitObject = reachedSearchLimit(err, data);
  if (searchLimitObject) {
    // The user hit a search limit so we're going to return their current API usage
    getQuota(options, (err, quota) => {
      if (err) {
        Logger.error(err, 'Error fetching user quota');
      }
      cb(null, {
        data: searchLimitObject,
        quota
      });
    });
  } else if (err) {
    return cb(err);
  } else {
    cb(null, {
      data: getDataHandler()
    });
  }
}

function onMessage(payload, options, cb) {
  const entity = payload.entity;
  switch (payload.searchType) {
    case 'whois':
      doDetailsLookup(
        {
          path: '/v2/whois',
          qs: { query: entity.value }
        },
        entity,
        options,
        (err, whois) => {
          onMessageResultHandler(err, whois, () => getBody(whois), options, cb);
        }
      );
      break;
    case 'pdns':
      doDetailsLookup({ path: '/v2/dns/passive', qs: { query: entity.value } }, entity, options, (err, pdns) => {
        onMessageResultHandler(
          err,
          pdns,
          () => orderBy('lastSeen', 'asc', getRecords(options.records, pdns)),
          options,
          cb
        );
      });
      break;
    case 'malware':
      doDetailsLookup(
        {
          path: '/v2/enrichment/malware',
          qs: { query: entity.value }
        },
        entity,
        options,
        (err, malware) => {
          onMessageResultHandler(err, malware, () => getRecords(options.records, malware), options, cb);
        }
      );
      break;
    case 'certificates':
      doDetailsLookup(
        {
          path: '/v2/ssl-certificate/search',
          qs: { query: entity.value, field: 'subjectCommonName' }
        },
        entity,
        options,
        (err, certificates) => {
          onMessageResultHandler(err, certificates, () => getRecords(options.records, certificates), options, cb);
        }
      );
      break;
    case 'pairs':
      doDetailsLookup(
        { path: '/v2/host-attributes/pairs', qs: { query: entity.value, direction: 'parents' } },
        entity,
        options,
        (parentErr, parentPairs) => {
          if (parentErr) return cb(parentErr);
          doDetailsLookup(
            { path: '/v2/host-attributes/pairs', qs: { query: entity.value, direction: 'children' } },
            entity,
            options,
            (childErr, childPairs) => {
              onMessageResultHandler(
                childErr,
                childPairs,
                () =>
                  flow(
                    concat(getRecords(options.records, parentPairs)),
                    uniqWith(isEqual)
                  )(getRecords(options.records, childPairs)),
                options,
                cb
              );
            }
          );
        }
      );
      break;
    case 'reputation':
      doDetailsLookup({ path: '/v2/reputation', qs: { query: entity.value } }, entity, options, (err, reputation) => {
        Logger.info({ reputation }, 'Reputation Result');
        onMessageResultHandler(err, reputation, () => getBody(reputation), options, cb);
      });
      break;
    case 'articles':
      doDetailsLookup(
        {
          path: '/v2/articles/indicator',
          qs: { query: entity.value }
        },
        entity,
        options,
        (err, articles) => {
          Logger.info({articles}, 'Articles');
          onMessageResultHandler(err, articles, () => getArticles(options.records, articles), options, cb);
        }
      );
      break;
    case 'articlesById':
      doDetailsLookup({ path: `/v2/articles/${payload.id}` }, entity, options, (err, article) => {
        onMessageResultHandler(err, article, () => article, options, cb);
      });
      break;
    case 'summary':
      doDetailsLookup({ path: '/v2/cards/summary', qs: { query: entity.value } }, entity, options, (err, summary) => {
        onMessageResultHandler(
          err,
          summary,
          () => {
            const lookupResult = createLookupResultObject(summary);
            return lookupResult.data.details.summary;
          },
          options,
          cb
        );
      });
      break;
    case 'quota':
      getQuota(options, (err, quota) => {
        if (err) return cb(err);
        cb(null, {
          quota
        });
      });
      break;
  }
}

function getQuota(options, cb) {
  // we can just use a dummy entity object here
  const entity = null;

  doDetailsLookup({ path: '/v2/account/quota' }, entity, options, (err, quota) => {
    if (err) {
      return cb(err);
    }

    Logger.info({ quota }, 'GOT QUOTA');
    cb(null, quota.body);
  });
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a PassiveTotal API key'
    });
  }

  if (
    typeof userOptions.user.value !== 'string' ||
    (typeof userOptions.user.value === 'string' && userOptions.user.value.length === 0)
  ) {
    errors.push({
      key: 'user',
      message: 'You must provide a PassiveTotal Username'
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
