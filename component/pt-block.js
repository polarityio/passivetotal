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
        articles: false
      });

      this.set('block._state.initialLoadAttempted', {
        summary: true,
        pdns: false,
        whois: false,
        malware: false,
        certificates: false,
        pairs: false,
        reputation: false,
        articles: false
      });
    }
  },
  setInitialLoadAttempted(type) {
    this.set(`block._state.initialLoadAttempted.${type}`, true);
  },
  getInitialLoadAttempted(type) {
    return this.get(`block._state.initialLoadAttempted.${type}`);
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      // Only attempt to load data once when users click on a tab
      if (this.getInitialLoadAttempted(tabName) === false) {
        this.runSearch(tabName);
      }
    },
    retrySearch: function (searchType) {
      this.runSearch(searchType);
    }
  },
  runSearch(searchType) {
    this.set(`block._state.searchRunning.${searchType}`, true);
    this.set('errorMsg', '');

    const payload = {
      searchType: searchType,
      entity: this.get('block.entity')
    };
    this.sendIntegrationMessage(payload)
      .then((result) => {
        this.set(`block.data.details.${searchType}`, result.data);
      })
      .catch((err) => {
        // there was an error
        if (this.isTimeoutError(error)) {
        } else {
          this.set('errorMessage', JSON.stringify(err, null, 4));
        }
      })
      .finally(() => {
        this.set(`block._state.searchRunning.${searchType}`, false);
        this.setInitialLoadAttempted(searchType);
      });
  },
  /**
   * Returns true if the onMessage error is a timeout
   * @param error
   * @returns {boolean}
   */
  isTimeoutError(error) {
    return error && error.status === '504';
  }
});
