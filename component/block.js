'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  summary: Ember.computed.alias('details.summary'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  activeTab: 'summary',
  errorMsg: '',
  runningRetrySearch: false,
  init() {
    this._super(...arguments);

    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.searchRunning', {
        summary: false,
        pdns: false,
        whois: false,
        malware: false,
        certificates: false,
        pairs: false,
        reputation: false,
        articles: false,
        quota: false,
        osnit: false
      });

      this.set('block._state.initialLoadAttempted', {
        summary: true,
        pdns: false,
        whois: false,
        malware: false,
        certificates: false,
        pairs: false,
        reputation: false,
        articles: false,
        osnit: false
      });
    }
  },
  hasWhoisAdmin: Ember.computed('details.whois.admin', function () {
    const admin = Object.keys(this.get('details.whois.admin'));
    return admin ? admin.length > 0 : false;
  }),
  hasWhoisTech: Ember.computed('details.whois.tech', function () {
    const tech = Object.keys(this.get('details.whois.tech'));
    return tech ? tech.length > 0 : false;
  }),
  hasWhoisRegistrant: Ember.computed('details.whois.registrant', function () {
    const registrant = Object.keys(this.get('details.whois.registrant'));
    return registrant ? registrant.length > 0 : false;
  }),
  articlesIsLoaded: Ember.computed('details.articles', function () {
    return Array.isArray(this.get('details.articles'));
  }),
  certificatesIsLoaded: Ember.computed('details.certificates', function () {
    return Array.isArray(this.get('details.certificates'));
  }),
  malwareIsLoaded: Ember.computed('details.malware', function () {
    return Array.isArray(this.get('details.malware'));
  }),
  pdnsIsLoaded: Ember.computed('details.pdns', function () {
    return Array.isArray(this.get('details.pdns'));
  }),
  pairsIsLoaded: Ember.computed('details.pairs', function () {
    return Array.isArray(this.get('details.pairs'));
  }),
  setInitialLoadAttempted(type) {
    this.set(`block._state.initialLoadAttempted.${type}`, true);
  },
  getInitialLoadAttempted(type) {
    return this.get(`block._state.initialLoadAttempted.${type}`);
  },
  actions: {
    changeTab: function (tabName) {
      console.log(tabName)
      this.set('activeTab', tabName);
      // Only attempt to load data once when users click on a tab
      if (this.getInitialLoadAttempted(tabName) === false) {
        this.runSearch(tabName);
      }
    },
    retrySearch: function (searchType) {
      this.runSearch(searchType);
    },
    showQuota: function () {
      this.toggleProperty(`block._state.viewQuota`);
      if (!this.get('details.quota')) {
        this.fetchQuota();
      }
    },
    getQuota: function () {
      this.fetchQuota();
    }
  },
  runSearch(searchType) {
    this.set(`block._state.searchRunning.${searchType}`, true);
    this.set('errorMsg', '');

    const payload = {
      searchType: searchType,
      entity: this.get('block.entity')
    };

    console.log(payload)

    this.sendIntegrationMessage(payload)
      .then((result) => {
        console.log('HELLO', result);
        this.set(`details.${searchType}`, result.data);
        // Note that quota won't always be defined.  We only return the quota if we ran into a search limit error
        this.set(`details.quota`, result.quota);
      })
      .catch((error) => {
        // timeout error occurs when the onMessage hook times out due to the endpoint taking too long
        if (this.isTimeoutError(error)) {
          if (!this.get(`details.${searchType}`)) {
            this.set(`details.${searchType}`, {});
          }
          this.set(`details.${searchType}.onMessageTimeout`, true);
        } else {
          this.set('errorMessage', JSON.stringify(error, null, 4));
        }
      })
      .finally(() => {
        this.set(`block._state.searchRunning.${searchType}`, false);
        this.setInitialLoadAttempted(searchType);
      });
  },
  fetchQuota() {
    this.set(`block._state.searchRunning.quota`, true);
    const payload = {
      searchType: 'quota'
    };
    this.sendIntegrationMessage(payload)
      .then((result) => {
        this.set(`details.quota`, result.quota);
      })
      .catch((error) => {})
      .finally(() => {
        this.set(`block._state.searchRunning.quota`, false);
      });
  },
  /**
   * Returns true if the onMessage error is a timeout
   * @param error
   * @returns {boolean}
   */
  isTimeoutError(error) {
    return error.status === '504';
  }
});
