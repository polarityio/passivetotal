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
  searchRunning: {
    summary: false,
    pdns: false,
    whois: false,
    malware: false,
    certificates: false,
    pairs: false,
    reputation: false
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      this.runSearch(tabName);
    },
    retrySearch: function (searchType) {
      this.runSearch(searchType);
    }
  },
  runSearch(searchType) {
    this.set(`searchRunning.${searchType}`, true);
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
        if(this.isTimeoutError(error)){

        } else {
          this.set('errorMessage', JSON.stringify(err, null, 4));
        }
      })
      .finally(() => {
        this.set(`searchRunning.${searchType}`, false);
      });
  },
  /**
   * Returns true if the onMessage error is a timeout
   * @param error
   * @returns {boolean}
   */
  isTimeoutError(error){
    return error && error.status === "504";
  }
});
