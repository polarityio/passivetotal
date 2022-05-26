module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'RiskIQ Community (PassiveTotal)',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'PT',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'RiskIQ Community (PassiveTotal) provides freemium threat hunting capabilities in order to surface threats faster and reduce risk.',
  entityTypes: ['domain', 'ipv4'],
  customTypes: [
    {
      key: 'trackerId',
      regex: /UA-[0-9]{4,9}(-[0-9]{1,4})?/
    }
  ],
  onDemandOnly: true,
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/pt.less'],
  defaultColor: 'light-blue',
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './component/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  summary: {
    component: {
      file: './component/summary.js'
    },
    template: {
      file: './templates/summary.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the PassiveTotal integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the PassiveTotal integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the PassiveTotal integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the PassiveTotal integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
  },
  logging: {
    level: 'trace' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'host',
      name: 'RiskIQ Community (PassiveTotal) API URL',
      description: 'The URL of the RiskIQ Community (PassiveTotal) API including the schema (i.e., https://)',
      default: 'https://api.passivetotal.org',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'user',
      name: 'API Username',
      description: 'Valid RiskIQ Community (PassiveTotal) Username',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description: 'Valid RiskIQ Community (PassiveTotal) API Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'records',
      name: 'Number of Associated Records to Return',
      description:
        'Total number of Malware and OSINT results to return in the Polarity Overlay. Please note the higher the number to longer it will take for the query to return',
      default: 10,
      type: 'number',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'searchHistorical',
      name: 'WHOIS historical data',
      description: 'Ability to search WHOIS historical data',
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'enableRep',
      name: 'Enable Reputation Lookup',
      description:
        'If checked, the integration will perform an optional onDetails API request to retrieve the entity reputation details.  This option requires additional privileged API access.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'enablePairs',
      name: 'Enable Host Pairs Lookup',
      description:
        'If checked, the integration will perform an optional onDetails API request to retrieve the entity host pairs details.  This option requires additional privileged API access.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blocklist',
      name: 'Ignore List',
      description: 'List of domains and IPs that you never want to send to PassiveTotal',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Ignore Domain Regex',
      description: 'Domains that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ipBlocklistRegex',
      name: 'Ignore IP Regex',
      description: 'IPs that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'maxConcurrent',
      name: 'Max Concurrent Search Requests',
      description:
        'Maximum number of concurrent search requests (defaults to 10).  Integration must be restarted after changing this option.',
      default: 10,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minTime',
      name: 'Minimum Time Between Searches',
      description:
        'Minimum amount of time in milliseconds between each entity search (defaults to 50).  Integration must be restarted after changing this option.',
      default: 50,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
