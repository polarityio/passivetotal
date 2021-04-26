'use strict';

const request = require('request');
const _ = require('lodash');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_ENTITY_LENGTH = 100;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

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

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      if (entity.type === 'custom') {
        tasks.push(
          doDetailsLookup(
            { path: '/v2/trackers/search', qs: { query: entity.value, type: 'GoogleAnalyticsTrackingId' } },
            entity,
            options
          )
        );
      } else {
        tasks.push(doDetailsLookup({ path: '/v2/cards/summary', qs: { query: entity.value } }, entity, options));
      }
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (
        !result.body ||
        result.body === null ||
        (result.entity.type != 'custom' &&
          result.body.data_summary.resolutions.count === 0 &&
          result.body.data_summary.certificates.count === 0 &&
          result.body.data_summary.hashes.count === 0 &&
          result.body.data_summary.projects.count === 0 &&
          result.body.data_summary.articles.count === 0 &&
          result.body.data_summary.trackers.count === 0 &&
          result.body.data_summary.components.count === 0 &&
          result.body.data_summary.host_pairs.count === 0 &&
          result.body.data_summary.cookies.count === 0)
      ) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else if (result.entity.type != 'custom') {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [
              'Resolutions: ' + result.body.data_summary.resolutions.count,
              'Certificates: ' + result.body.data_summary.certificates.count,
              'Hashes: ' + result.body.data_summary.hashes.count,
              'Projects: ' + result.body.data_summary.projects.count,
              'Articles: ' + result.body.data_summary.articles.count,
              'Trackers: ' + result.body.data_summary.trackers.count,
              'Components: ' + result.body.data_summary.components.count,
              'Host Pairs: ' + result.body.data_summary.host_pairs.count,
              'Cookies: ' + result.body.data_summary.cookies.count
            ],
            details: result.body
          }
        });
      } else {
        result.body.results = result.body.results.splice(0, options.records);

        result.body.results.forEach((tracker) => {
          tracker = Object.keys(tracker).length > 0;
        });

        lookupResults.push({
          entity: result.entity,
          data: {
            summary: ['Trackers:' + result.body.results.length],
            details: {
              tracker: result.body.results
            }
          }
        });
      }
    });

    Logger.trace({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function doDetailsLookup(request, entity, options) {
  return function (done) {
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
        done(processedResult.error);
        return;
      }
      Logger.trace({ processedResult }, 'Looking at the Result');
      done(null, processedResult);
    });
  };
}

function onDetails(lookupObject, options, cb) {
  let entity = lookupObject.entity;
  if (entity.type === 'domain' || entity.type === 'IPv4' && options.enableRep === true) {
    async.parallel(
      {
        malware: doDetailsLookup({ path: '/v2/enrichment/malware', qs: { query: entity.value } }, entity, options),
        osint: doDetailsLookup({ path: '/v2/enrichment/osint', qs: { query: entity.value } }, entity, options),
        reputation: doDetailsLookup({ path: '/v2/reputation', qs: { query: entity.value } }, entity, options)
      },
      (err, results) => {
        if (err) {
          return cb(err);
        }

        lookupObject.data.details.malware = [];
        lookupObject.data.details.osint = [];
        lookupObject.data.details.reputation = [];

        if (results.malware.body !== null) {
          lookupObject.data.details.malware = results.malware.body.results.splice(0, options.records);
        }

        if (results.osint.body !== null) {
          lookupObject.data.details.osint = results.osint.body.results.splice(0, options.records);
        }

        if (results.reputation.body !== null) {
          lookupObject.data.details.reputation = results.reputation.body;
        }

        Logger.trace({ lookup: lookupObject.data }, 'Looking at the data after on details.');

        cb(null, lookupObject.data);
      }
    );
  } else if (entity.type === 'domain' || entity.type === 'IPv4' && options.enableRep != true){
    async.parallel(
      {
        malware: doDetailsLookup({ path: '/v2/enrichment/malware', qs: { query: entity.value } }, entity, options),
        osint: doDetailsLookup({ path: '/v2/enrichment/osint', qs: { query: entity.value } }, entity, options)
      },
      (err, results) => {
        if (err) {
          return cb(err);
        }

        lookupObject.data.details.malware = [];
        lookupObject.data.details.osint = [];

        if (results.malware.body !== null) {
          lookupObject.data.details.malware = results.malware.body.results.splice(0, options.records);
        }

        if (results.osint.body !== null) {
          lookupObject.data.details.osint = results.osint.body.results.splice(0, options.records);
        }

        Logger.trace({ lookup: lookupObject.data }, 'Looking at the data after on details.');

        cb(null, lookupObject.data);
      }
    );
  }
  else {
    cb(null, lookupObject.data);
  }
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
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
  doLookup: doLookup,
  onDetails: onDetails,
  startup: startup,
  validateOptions: validateOptions
};
