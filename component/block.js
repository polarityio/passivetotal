'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  summary: Ember.computed.alias('details.summary'),
  itemsPerPage: 50,
  serviceStates: {},
  recentServiceStates: {},
  currentServiceStates: {},
  subdomainStates: {},
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  enabledDataSourcesMisconfigured: Ember.computed('block.userOptions.enabledDatasources', function () {
    const enabledDatasources = this.get('block.userOptions.enabledDatasources');
    return !enabledDatasources;
  }),
  /**
   * Returns an object where the key is the datasource name and the value is a true/false
   * boolean for whether the datasource is enabled.  This is controlled by the user option
   * and is used in the templates to hide disabled datasources.  V
   *
   * Valid datasources are:
   *
   * resolutions
   * hostPairs
   * malware
   * services
   * reputation
   * articles
   * sslCerts
   * osint
   * subdomains
   */
  enabledDatasources: Ember.computed('block.userOptions.enabledDatasources', function () {
    const enabledDatasources = this.get('block.userOptions.enabledDatasources');
    if (enabledDatasources) {
      const enabledDatasourcesAsMap = enabledDatasources.reduce((accum, datasource) => {
        accum[datasource.value] = true;
        return accum;
      }, {});

      return enabledDatasourcesAsMap;
    } else {
      console.error(
        'The "Enabled Datasources" option must be set to "Users can view only" or "Users can view and edit"'
      );
      return {};
    }
  }),
  activeTab: 'summary',
  showInsights: false,
  showServices: false,
  pairs: false,
  errorMsg: '',
  runningRetrySearch: false,
  resolutionSortOptions: [
    {
      display: 'Last Seen',
      value: 'lastSeenSeconds'
    },
    {
      display: 'First Seen',
      value: 'firstSeenSeconds'
    },
    {
      display: 'Collected',
      value: 'collectedSeconds'
    }
  ],
  resolutionSortOrderOptions: ['Ascending', 'Descending'],
  resolutions: Ember.computed(
    'details.pdns.data.pdnsData',
    'block._state.resolutions.sortValue',
    'block._state.resolutions.sortOrder',
    'block._state.resolutions.endItem',
    'block._state.resolutions.startItem',
    'block._state.resolutions.filter',
    function () {
      const sortValue = this.get('block._state.resolutions.sortValue');
      const sortOrder = this.get('block._state.resolutions.sortOrder');
      const filter = this.get('block._state.resolutions.filter');

      let filteredResolutions;
      let sortedResolutions;
      let slicedResolutions;

      // Only run the filter if we need to
      if (filter !== this.get('block._state.resolutions.previousFilter')) {
        filteredResolutions = this.get('details.pdns.data.pdnsData').filter((item) => {
          return item.resolve.includes(filter);
        });
        this.set('block._state.resolutions.filteredTotal', filteredResolutions.length);
        // Anytime we change the filter we want to reset back to the first page
        this.changePage('firstPage');
      } else {
        filteredResolutions = this.get('details.pdns.data.pdnsData');
        this.set('block._state.resolutions.filteredTotal', filteredResolutions.length);
      }

      this.set('block._state.resolutions.previousFilter', filter);

      sortedResolutions = filteredResolutions.sort((a, b) => {
        return sortOrder === 'Descending' ? b[sortValue] - a[sortValue] : a[sortValue] - b[sortValue];
      });

      slicedResolutions = sortedResolutions.slice(
        this.get('block._state.resolutions.startItem') - 1,
        this.get('block._state.resolutions.endItem')
      );

      return slicedResolutions;
    }
  ),
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
        subdomains: false,
        osint: false,
        services: false,
        insights: false
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
        subdomains: false,
        osint: false,
        services: false,
        insights: false
      });

      // used to toggle whether a particular data type is visible
      this.set('block._state.visible', {
        summary: true,
        pdns: false,
        whois: false,
        malware: false,
        certificates: false,
        pairs: false,
        reputation: false,
        articles: false,
        subdomains: false,
        osint: false,
        services: false,
        insights: false
      });

      // used to expand all the results within a data type
      // A result can only be expanded if the the data type is visible
      this.set('block._state.expanded', {
        summary: false,
        pdns: false,
        whois: false,
        malware: false,
        certificates: false,
        pairs: false,
        reputation: false,
        articles: false,
        subdomains: false,
        osint: false,
        services: false,
        insights: false
      });

      this.set('showInsights', this.get('details.insights'));
      this.set('block._state.resolutions', {});
      this.set('block._state.resolutions.sortValue', 'lastSeenSeconds');
      this.set('block._state.resolutions.sortOrder', 'Descending');
      this.set('block._state.resolutions.pageNumber', 1);
      this.set('block._state.resolutions.startItem', 1);
      this.set('block._state.resolutions.endItem', this.get('itemsPerPage'));
      this.set('block._state.resolutions.filter', '');
      this.set('block._state.resolutions.filteredTotal', 0);
      this.get('block._state.resolutions.previousFilter', '');
      this.set('block._state.resolutions.shadowFilter', '');
    }
  },
  malwareIsLoaded: Ember.computed('details.malware.data', function () {
    return Array.isArray(this.get('details.malware.data'));
  }),
  pdnsIsLoaded: Ember.computed('details.pdns.data.pdnsData', function () {
    return Array.isArray(this.get('details.pdns.data.pdnsData'));
  }),
  setInitialLoadAttempted(type) {
    this.set(`block._state.initialLoadAttempted.${type}`, true);
  },
  getInitialLoadAttempted(type) {
    return this.get(`block._state.initialLoadAttempted.${type}`);
  },
  actions: {
    toggleExpanded: function (type) {
      this.toggleProperty(`block._state.expanded.${type}`);
    },
    clearError() {
      this.set('errorMessage', '');
    },
    /**
     * Triggered when a user toggles a historic WHOIS record to show the details.  The index is into
     * the whois records array of results.
     * @param index
     */
    toggleWhoisRecord: function (index) {
      this.toggleProperty('details.whois.data.whoisData.' + index + '._isVisible');
    },
    filterResolutions: function () {
      this.set('block._state.resolutions.filter', this.get('block._state.resolutions.shadowFilter'));
    },
    clearResolutionFilter: function () {
      this.set('block._state.resolutions.filter', '');
      this.set('block._state.resolutions.shadowFilter', '');
    },
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      // Only attempt to load data once when users click on a tab
      if (this.getInitialLoadAttempted(tabName) === false) {
        this.runSearch(tabName);
      }
    },
    setPage: function (value) {
      this.changePage(value);
    },

    toggleShowResults: function (searchType) {
      this.toggleProperty(`block._state.visible.${searchType}`);

      if (this.getInitialLoadAttempted(searchType) === false) {
        this.runSearch(searchType);
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
    },
    toggleExpandableRecentServiceTitle: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('recentServiceStates'), {
        [index]: !this.get('recentServiceStates')[index]
      });

      this.set(`recentServiceStates`, modifiedExpandableTitleStates);
    },
    toggleExpandableCurrentServiceTitle: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('currentServiceStates'), {
        [index]: !this.get('currentServiceStates')[index]
      });

      this.set(`currentServiceStates`, modifiedExpandableTitleStates);
    },
    toggleExpandableSubdomains: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('subdomainStates'), {
        [index]: !this.get('subdomainStates')[index]
      });

      this.set(`subdomainStates`, modifiedExpandableTitleStates);
    }
  },
  changePage(value) {
    const perPage = this.get('itemsPerPage');
    const pageNumber = this.get('block._state.resolutions.pageNumber');
    const totalItems = this.get('block._state.resolutions.filteredTotal');
    const minPage = 1;
    const maxPage = Math.ceil(totalItems / perPage);
    let tempPageNumber;
    if (value === 'firstPage') {
      tempPageNumber = 1;
    } else if (value === 'lastPage') {
      tempPageNumber = maxPage;
    } else {
      tempPageNumber = pageNumber + value;
    }

    // Can't go below min page (1) or above max page
    if (tempPageNumber < minPage || tempPageNumber > maxPage) {
      return;
    }

    const startItem = (tempPageNumber - 1) * perPage + 1;
    const endItem = tempPageNumber * perPage > totalItems ? totalItems : tempPageNumber * perPage;

    this.set('block._state.resolutions.startItem', startItem);
    this.set('block._state.resolutions.endItem', endItem);
    this.set('block._state.resolutions.pageNumber', tempPageNumber);
  },
  runSearch(searchType) {
    this.set(`block._state.searchRunning.${searchType}`, true);
    this.set('errorMsg', '');

    const payload = {
      searchType: searchType,
      entity: this.get('block.entity')
    };

    if (!this.get(`details.${searchType}`)) {
      this.set(`details.${searchType}`, {});
    }

    this.sendIntegrationMessage(payload)
      .then((result) => {
        this.set('errorMessage', '');
        this.set(`details.${searchType}.accessDenied`, false);
        this.set(`details.${searchType}.onMessageTimeout`, false);
        const typeDetails = this.get(`details.${searchType}`);
        this.set(`details.${searchType}`, Object.assign({}, typeDetails, result));
        // Note that quota won't always be defined.  We only return the quota if we ran into a search limit error
        this.set(`details.quota`, result.quota);
      })
      .catch((error) => {
        // timeout error occurs when the onMessage hook times out due to the endpoint taking too long
        if (this.isTimeoutError(error)) {
          this.set(`details.${searchType}.onMessageTimeout`, true);
        } else if (error.meta && error.meta.accessDenied) {
          this.set(`details.${searchType}.accessDenied`, true);
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
