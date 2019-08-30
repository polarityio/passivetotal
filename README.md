# Polarity PassiveTotal Integration

![mode:on demand only](https://img.shields.io/badge/mode-on%20demand%20only-blue.svg)

> As whois lookups return data on nearly every domain, we recommend running this integration in "On-Demand" mode only.

The Polarity - PassiveTotal integration searches PassiveTotal for Whois information on domains and emails. For domains, the integration will additionally retrieve malware and open source intelligence in the details.

To learn more about PassiveTotal, please visit the [official website](https://www.riskiq.com/products/passivetotal/).


Check out the integration in action:

![passivetotal](images/overlay.gif)

## PassiveTotal Requests

The Polarity-PassiveTotal integration runs whois lookups against both emails and domains.  For domains, the integration will do a details lookup against malware and open source intelligence endpoints.

| Entity Type | REST API Endpoints Searched | 
|------------|-----------------------------|
| domain | https://api.passivetotal.org/v2/whois/search <br> https://api.passivetotal.org/v2/enrichment/malware (on details) <br> https://api.passivetotal.org/v2/enrichment/osint (on details)|
| email | https://api.passivetotal.org/v2/whois/search |
## PassiveTotal Integration Options

### PassiveTotal Api URL
The URL of the PassiveTotal API including the schema (i.e., https://). Default is set to:  https://api.passivetotal.org

### PassiveTotal Api Username
PassiveTotal Username, used to access the API.

### PassiveTotal ApiKey
PassiveTotal API Key

### Number of Associated Records to Return
Number of associated Malware, pDNS and OSINT records to return. Please note the higher the number to longer it will take for the query to return. Default is set to 10.

### Blacklist Domains
List of domains  that you never want to send to Domain Tools

### Domain Blacklist Regex
Domains that match the given regex will not be looked up (if blank, no domains will be black listed)


## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
