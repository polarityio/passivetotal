'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  activeTab: 'summary',
  errorMsg: '',
  actions: {
    changeTab: function(tabName) {
      this.set('activeTab', tabName);
    }
  },
  onDetailsError(err) {
    this.set('errorMessage', err.meta.detail);
  }
});
