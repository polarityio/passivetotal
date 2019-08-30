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
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;

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

function _setupRegexBlacklists(options) {
  if (options.domainBlacklistRegex !== previousDomainRegexAsString && options.domainBlacklistRegex.length === 0) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug({ domainBlacklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blacklist Regex');
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
    }
  }

  if (options.ipBlacklistRegex !== previousIpRegexAsString && options.ipBlacklistRegex.length === 0) {
    Logger.debug('Removing IP Blacklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlacklistRegex = null;
  } else {
    if (options.ipBlacklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlacklistRegex;
      Logger.debug({ ipBlacklistRegex: previousIpRegexAsString }, 'Modifying IP Blacklist Regex');
      ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
    }
  }
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlacklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlacklisted(entity, options)) {
      tasks.push(
        doDetailsLookup({ path: '/v2/whois/search', qs: { query: entity.value, field: entity.type } }, entity, options)
      );
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        result.body.results = result.body.results.splice(0, options.records);

        result.body.results.forEach((whois) => {
          whois.hasTech = Object.keys(whois.tech).length > 0;
          whois.hasBilling = Object.keys(whois.billing).length > 0;
          whois.hasRegistrant = Object.keys(whois.registrant).length > 0;
          whois.hasAdmin = Object.keys(whois.admin).length > 0;
        });

        lookupResults.push({
          entity: result.entity,
          data: {
            summary: _getSummaryTags(result.entity, result.body.results),
            details: {
              whois: result.body.results
            }
          }
        });
      }
    });

    Logger.trace({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function _getSummaryTags(entity, results) {
  let tagMap = new Map();
  results.forEach((result) => {
    if (entity.type === 'email') {
      tagMap.set(result.name.toLowerCase(), result.name);
      if (result.hasRegistrant) {
        tagMap.set(result.registrant.country.toLowerCase(), result.registrant.country);
      }
    }
    if (entity.type === 'domain') {
      if (result.organization !== 'N/A') {
        tagMap.set(result.organization.toLowerCase(), `Org: ${result.organization}`);
      }

      tagMap.set(result.registrar.toLowerCase(), `Registrar: ${result.registrar}`);

      if (result.hasRegistrant) {
        tagMap.set(result.registrant.country.toLowerCase(), `Country: ${result.registrant.country}`);
      }
    }
  });
  return [...tagMap.values()];
}

function doDetailsLookup(request, entity, options) {
  return function(done) {
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

    requestWithDefaults(requestOptions, (error, response, body) => {
      let processedResult = handleRestError(error, entity, response, body);

      if (processedResult.error) {
        done(processedResult.error);
        return;
      }

      done(null, processedResult);
    });
  };
}

function onDetails(lookupObject, options, cb) {
  let entity = lookupObject.entity;
  if (entity.type === 'domain') {
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
  } else {
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

  if (res.statusCode === 200 && Array.isArray(body.results) && body.results.length > 0) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (
    (res.statusCode === 200 && Array.isArray(body.results) && body.results.length === 0) ||
    res.statusCode === 404
  ) {
    // no result found
    result = {
      entity: entity,
      body: null
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

function _isEntityBlacklisted(entity, options) {
  const blacklist = options.blacklist;

  Logger.trace({ blacklist: blacklist }, 'checking to see what blacklist looks like');

  if (_.includes(blacklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlacklistRegex !== null) {
      if (ipBlacklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlackListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlackListed Domain Lookup');
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
