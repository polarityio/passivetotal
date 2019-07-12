module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'PassiveTotal',
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
    'PassiveTotal centralizes numerous data sets into a single platform, making it easier for our community and customers to conduct infrastructure analysis. Our primary focus is to provide as much data as possible about Internet infrastructure.',
  entityTypes: ['domain', 'IPv4'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/pt.less'],
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
      file: './component/pt-block.js'
    },
    template: {
      file: './templates/pt-block.hbs'
    }
  },
  summary: {
      component: {
          file: './component/pt-summary.js'
      },
      template: {
          file: './templates/pt-summary.hbs'
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
    level: 'info' //trace, debug, info, warn, error, fatal
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
      name: 'PassiveTotal API URL',
      description: 'The URL of the PassiveTotal API including the schema (i.e., https://)',
      default: 'https://api.passivetotal.org',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'user',
      name: 'API Username',
      description: 'Valid PassiveTotal Username',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description: 'Valid PassiveTotal API Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'records',
      name: 'Number of Associated Records to Return',
      description: 'Number of associated Malware, pDNS and OSINT records to return. Please note the higher the number to longer it will take for the query to return',
      default: 10,
      type: 'number',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blacklist',
      name: 'Blacklist Domains and IPs',
      description: 'List of domains and IPs that you never want to send to PassiveTotal',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlacklistRegex',
      name: 'Domain Black List Regex',
      description:
        'Domains that match the given regex will not be looked up (if blank, no domains will be black listed)',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ipBlacklistRegex',
      name: 'IP Black List Regex',
      description: 'IPs that match the given regex will not be looked up (if blank, no IPs will be black listed)',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
