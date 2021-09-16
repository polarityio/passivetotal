/*
 * Copyright (c) 2021, Polarity.io, Inc.
 */

'use strict';
polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    summary: Ember.computed.alias('block.data.details.summary')
});
