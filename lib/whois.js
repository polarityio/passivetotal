/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */
const jsondiffpatch = require('jsondiffpatch');
const _ = require('lodash');

const whoisTemplate = [
  {
    type: 'title',
    icon: 'info',
    display: 'Info'
  },
  {
    type: 'text',
    display: 'WHOIS Server',
    path: 'whoisServer'
  },
  {
    type: 'text',
    display: 'Domain',
    path: 'domain'
  },
  {
    type: 'text',
    display: 'Domain Status',
    path: 'domainStatus'
  },
  {
    type: 'text',
    display: 'Name',
    path: 'name'
  },
  {
    type: 'text',
    display: 'Organization',
    path: 'organization'
  },
  {
    type: 'text',
    display: 'Telephone',
    path: 'telephone'
  },
  {
    type: 'text',
    display: 'Contact Email',
    path: 'contactEmail'
  },
  {
    type: 'text',
    display: 'Registrar',
    path: 'registrar'
  },
  {
    type: 'date',
    display: 'Expires At',
    path: 'expiresAt'
  },
  {
    type: 'date',
    display: 'Last Loaded At',
    path: 'lastLoadedAt'
  },
  {
    type: 'date',
    display: 'Registered',
    path: 'registered'
  },
  {
    type: 'date',
    display: 'Registry Updated At',
    path: 'registryUpdatedAt'
  },
  {
    type: 'list',
    icon: 'server',
    display: 'Name Servers',
    path: 'nameServers'
  },
  // Admin Section
  {
    type: 'title',
    icon: 'user-cog',
    display: 'Admin',
    // If a path is provided we will check if the path exists before displaying the title
    path: 'admin'
  },
  {
    type: 'text',
    display: 'Name',
    path: 'admin.name'
  },
  {
    type: 'text',
    display: 'Organization',
    path: 'admin.organization'
  },
  {
    type: 'text',
    display: 'Email',
    path: 'admin.email'
  },
  {
    type: 'text',
    display: 'Telephone',
    path: 'admin.telephone'
  },
  {
    type: 'text',
    display: 'Street',
    path: 'admin.street'
  },
  {
    type: 'text',
    display: 'Postal Code',
    path: 'admin.postalCode'
  },
  {
    type: 'text',
    display: 'City',
    path: 'admin.city'
  },
  {
    type: 'text',
    display: 'State',
    path: 'admin.state'
  },
  {
    type: 'text',
    display: 'Country',
    path: 'admin.country'
  },
  // Registrant Section
  {
    type: 'title',
    icon: 'user-tie',
    display: 'Registrant',
    // If a path is provided we will check if the path exists before displaying the title
    path: 'registrant'
  },
  {
    type: 'text',
    display: 'Name',
    path: 'registrant.name'
  },
  {
    type: 'text',
    display: 'Organization',
    path: 'registrant.organization'
  },
  {
    type: 'text',
    display: 'Email',
    path: 'registrant.email'
  },
  {
    type: 'text',
    display: 'Telephone',
    path: 'registrant.telephone'
  },
  {
    type: 'text',
    display: 'Street',
    path: 'registrant.street'
  },
  {
    type: 'text',
    display: 'Postal Code',
    path: 'registrant.postalCode'
  },
  {
    type: 'text',
    display: 'City',
    path: 'registrant.city'
  },
  {
    type: 'text',
    display: 'State',
    path: 'registrant.state'
  },
  {
    type: 'text',
    display: 'Country',
    path: 'registrant.country'
  },
  // Tech Section
  {
    type: 'title',
    icon: 'user-visor',
    display: 'Tech',
    // If a path is provided we will check if the path exists before displaying the title
    path: 'tech'
  },
  {
    type: 'text',
    display: 'Name',
    path: 'tech.name'
  },
  {
    type: 'text',
    display: 'Organization',
    path: 'tech.organization'
  },
  {
    type: 'text',
    display: 'Email',
    path: 'tech.email'
  },
  {
    type: 'text',
    display: 'Telephone',
    path: 'tech.telephone'
  },
  {
    type: 'text',
    display: 'Street',
    path: 'tech.street'
  },
  {
    type: 'text',
    display: 'Postal Code',
    path: 'tech.postalCode'
  },
  {
    type: 'text',
    display: 'City',
    path: 'tech.city'
  },
  {
    type: 'text',
    display: 'State',
    path: 'tech.state'
  },
  {
    type: 'text',
    display: 'Country',
    path: 'tech.country'
  }
];
const whoisServerFields = ['domainStatus', 'whoisServer', 'registrar'];
const whoisEmailFields = ['contactEmail', 'admin.email', 'tech.email', 'billing.email', 'registrant.email'];
const whoisPhoneFields = [
  'admin.telephone',
  'admin.fax',
  'tech.telephone',
  'tech.fax',
  'billing.telephone',
  'billing.fax',
  'registrant.telephone',
  'registrant.fax',
  'fax',
  'telephone'
];
const whoisOrgFields = [
  'admin.country',
  'admin.organization',
  'admin.state',
  'admin.city',
  'admin.street',
  'admin.organization',
  'admin.postalCode',
  'admin.name',

  'billing.country',
  'billing.organization',
  'billing.state',
  'billing.city',
  'billing.street',
  'billing.organization',
  'billing.postalCode',
  'billing.name',

  'tech.country',
  'tech.organization',
  'tech.state',
  'tech.city',
  'tech.street',
  'tech.organization',
  'tech.postalCode',
  'tech.name',

  'registrant.country',
  'registrant.organization',
  'registrant.state',
  'registrant.city',
  'registrant.street',
  'registrant.organization',
  'registrant.postalCode',
  'registrant.name'
];

/**
 * Match on non-numbers
 */
const matchAllNonNumbersRegex = /[^0-9]/g;

/**
 * Given an input phone number, removes all non-digit characters.  This is used to normalize
 * phone number comparison when computing diffs.
 *
 * @param phoneNumber
 * @returns {*}
 */
function normalizePhoneNumber(phoneNumber) {
  return phoneNumber.replace(matchAllNonNumbersRegex, '');
}

/**
 * Test if the given `value` is a plaint javascript object
 *
 * https://stackoverflow.com/questions/41311098/typeof-object-but-not-array
 *
 * @param value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return value instanceof Object && Object.getPrototypeOf(value) == Object.prototype;
}

/**
 * Historical whois information is sorted by the `registryUpdatedAt` date.  We then compare each whois record with
 * the next sorted record to see if there are any changes in the following five categories:
 * email, phone, org, nameServers, servers.
 *
 * If there is no change, then we drop the record and compare to the next one until we find a diff.  We only
 * keep records that have a valid diff (i.e., there was a change).  In addition, we don't diff all fields.
 * We are using the `jsondiffpatch` library to do the diff logic.
 *
 * As an example, suppose we had the following WHOIS records.  We have sorted these in order so that index0
 * is the most recent and the last index is the oldest WHOIS record.
 *
 * A -- content1
 * B -- content1
 * C -- content2
 * D -- content3
 * E -- content3
 * F -- content3
 * G -- content4
 *
 * We start with A and compare it B, since the content is the same we drop B and compare A to C.  Since there is
 * a difference in content we keep C and we now compare C to D. Again the content is different so we keep D and now
 * compare D to E.  D and E are the same so we compare D and F. D and F are the same so we compare D and G.  Since
 * D and G are different we keep G.  At the end we have the following records kept:
 *
 * A -- content1
 * C -- content2
 * D -- content3
 * G -- content4
 *
 *
 *
 *
 * Organization Fields: See `whoisOrgFields`
 *
 * Email: See `whoisEmailFields`
 *
 * Phone fields: See `whoisPhoneFields`
 *
 * Name Servers fields: nameServers (Array), note this is a single field for this category
 *
 * Server fields: See `whoisServerFields`
 *
 * @param whois
 */
function computeHistoricalWhoisDiff(whois, Logger) {
  // Add epoch time in seconds field for use in sorting and remove any records where
  // the `registryUpdatedAt` does not exist.  The PassiveTotal web interface seems to
  // remove these records from being displayed
  whois = whois.reduce((accum, record) => {
    if (record.registryUpdatedAt) {
      record.registryUpdatedAtEpochSeconds = new Date(record.registryUpdatedAt).getTime() / 1000;

      // We want to take an keys that are empty objects and make them null.  We do this because
      // it is easier to test for empty arrays in an Ember template than an empty object.  In our
      // templates we don't want to display data that is empty.
      for (const [key, value] of Object.entries(record)) {
        // If the value is a plain object and empty, change it to null
        if (isPlainObject(value) && Object.keys(value).length === 0) {
          record[key] = null;
        }
      }

      accum.push(record);
    }

    return accum;
  }, []);

  // Sort whois records by registryUpdatedAt time descending (most recent first)
  whois.sort((a, b) => {
    return b.registryUpdatedAtEpochSeconds - a.registryUpdatedAtEpochSeconds;
  });

  // Remove fields we don't want to include as part of the diff process
  // Essentially, all date based fields are removed.
  const whoisDiffObject = whois.map((record) => {
    let recordToDiff = {
      ...record
    };
    delete recordToDiff.expiresAt;
    delete recordToDiff.lastLoadedAt;
    delete recordToDiff.registered;
    delete recordToDiff.registryUpdatedAt;
    delete recordToDiff.registryUpdatedAtEpochSeconds;

    // Normalize all the phone number fields
    whoisPhoneFields.forEach((phoneField) => {
      if (_.has(recordToDiff, phoneField)) {
        let phoneNumber = _.get(recordToDiff, phoneField);
        _.set(recordToDiff, phoneField, normalizePhoneNumber(phoneNumber));
      }
    });

    return recordToDiff;
  });

  // Diff each whois record with the one before it (chronologically) (i.e., the index after in the array).
  // If there are no changes remove the older record and re-diff with the next record.
  // For each whois record that we keep compute a diff summary.
  const minimizedWhoisData = [];
  let sourceIndex = 0;
  // let targetIndex = 1;
  // let maxSourceIndex = whoisDiffObject.length - 2;
  // let maxTargetIndex = whoisDiffObject.length - 1;
  Logger.trace(
    {
      numRecords: whois.length,
      maxIndex: whois.length - 1,
      diffObjectLength: whoisDiffObject.length
    },
    'Record meta'
  );

  // This customDiffPatch is setup so that string diffs are a straight string comparison.
  // If you don't do this then you will get a string diff object which is more complex than
  // we want for our integration (i.e., it will show you which characters were changed within
  // a string)
  const customDiffPatch = jsondiffpatch.create({
    textDiff: {
      minLength: 2000 // Just do a string comparison for strings up to length 2000
    }
  });

  for (let targetIndex = 1; targetIndex <= whoisDiffObject.length - 1; targetIndex++) {
    Logger.trace('Diffing source ' + sourceIndex + ' against target ' + targetIndex);
    let diffResult = customDiffPatch.diff(whoisDiffObject[targetIndex], whoisDiffObject[sourceIndex]);

    // mutates diffResult.  Removes diff results we don't want (e.g., we ignore diffs where the only
    // difference is the casing.  Will return a null object if we end up removing all the keys.
    diffResult = scrubDiffResult(diffResult);
    Logger.trace({ diffResult }, 'Diff Result');

    if (diffResult) {
      // Generate a diff summary object which we use in the template
      const diffSummary = computeWhoisDiffSummary(diffResult);
      minimizedWhoisData.push({
        data: whois[sourceIndex],
        diff: diffResult,
        diffSummary
      });
      //Logger.info('Pushed index ' + sourceIndex);
      sourceIndex = targetIndex;
    }
  }

  // The last whois history object is the "first" whois record so there is nothing to diff it with
  // we just add that to the end of the array of records.  In the PassiveTotal interface, the display
  // this first record as having all categories changed in the diff summary so we manually add a diff summary
  // object to this affect.
  minimizedWhoisData.push({
    data: whois[whoisDiffObject.length - 1],
    diff: null,
    diffSummary: {
      email: true,
      phone: true,
      nameServers: true,
      org: true,
      whoisServer: true
    }
  });

  return minimizedWhoisData;
}

/**
 * When using the jsondiffpatch library it will find diffs we don't care about.  This
 * method goes through the diff object and removes and results we don't actually want to treat as
 * a diff.  There are two primary things we check for:
 *
 * 1. We want to ignore changes in order when diffing the nameserver array.  The default is to
 *    consider a change in the order of an array as a change.  For our purposes we don't care about
 *    this and only care if a new entry is added somewhere in the array, or if an existing entry is removed.
 *
 *    See: https://github.com/benjamine/jsondiffpatch/issues/79 for how we do this.
 *
 * 2. We don't care about case sensitivity when comparings values.  If the only change is a change in case
 *    then we don't consider it a change.
 *
 * @param diffObject
 * @returns {{nameServers}|*|null}
 */
function scrubDiffResult(diffObject) {
  if (typeof diffObject === 'undefined' || diffObject === null) {
    return diffObject;
  }

  // when comparing name servers we want to ignore diffs that are only of array changes
  if (diffObject && diffObject.nameServers) {
    const keys = Object.keys(diffObject.nameServers);
    keys.forEach((key) => {
      if (Array.isArray(diffObject.nameServers[key]) && diffObject.nameServers[key][2] === 3) {
        delete diffObject.nameServers[key];
      } else if (key === '_t') {
        delete diffObject.nameServers[key];
      }
    });

    if (Object.keys(diffObject.nameServers).length === 0) {
      delete diffObject.nameServers;
    }

    // check if diffObject is now empty
    if (Object.keys(diffObject).length === 0) {
      return null;
    }
  }

  // Remove any diffs where the only difference between the strings is the case
  // (i.e., we only want to keep case insensitive diff results)
  const ignoreCasingFields = whoisOrgFields.concat(whoisServerFields);
  for (const field of ignoreCasingFields) {
    if (_.has(diffObject, field)) {
      const value = _.get(diffObject, field);
      if (Array.isArray(value) && value.length === 2) {
        if (value[0].toLowerCase() === value[1].toLowerCase()) {
          _.unset(diffObject, field);
        }
      }
    }
  }

  // We may now have empty top level objets due to the nested `admin`, `tech`, `registrant`, and `billing` keys
  // which could have have sub keys removed.  Run through and remove any empty top level keys
  const topLevelKeys = Object.keys(diffObject);
  for (const key of topLevelKeys) {
    if (Object.keys(diffObject[key]).length === 0) {
      _.unset(diffObject, key);
    }
  }

  if (Object.keys(diffObject).length === 0) {
    return null;
  }

  return diffObject;
}

/**
 * This method categorizes the diff into 4 possible categories which are:
 * email, phone, org, nameServers, and whoisServer
 *
 * @param diffObject
 * @returns {Object}
 */
function computeWhoisDiffSummary(diffObject) {
  const diffSummary = {
    email: false,
    phone: false,
    nameServers: false,
    org: false,
    whoisServer: false
  };

  if (!diffObject) {
    return diffSummary;
  }

  for (const field of whoisEmailFields) {
    if (_.get(diffObject, field)) {
      diffSummary.email = true;
      break;
    }
  }

  for (const field of whoisPhoneFields) {
    if (_.get(diffObject, field)) {
      diffSummary.phone = true;
      break;
    }
  }

  for (const field of whoisServerFields) {
    if (_.get(diffObject, field)) {
      diffSummary.whoisServer = true;
      break;
    }
  }

  if (diffObject.nameServers) {
    diffSummary.nameServers = true;
  }

  for (const field of whoisOrgFields) {
    if (_.get(diffObject, field)) {
      diffSummary.org = true;
      break;
    }
  }

  return diffSummary;
}

module.exports = {
  whoisTemplate,
  computeHistoricalWhoisDiff
};
