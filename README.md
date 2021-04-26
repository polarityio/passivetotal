# Polarity RiskIQ Community (PassiveTotal) Integration

![mode:on demand only](https://img.shields.io/badge/mode-on%20demand%20only-blue.svg)

> As lookups return data on nearly every IPv4 address and domain, we recommend running this integration in "On-Demand" mode only.

The Polarity RiskIQ Community (PassiveTotal) integration retrieves the "Data Summary Card" for both IPv4 addresses and domains. The integration will also perform an on-details lookup against malware and open source intelligence endpoints.  Furthermore, the integration will also recognize Google Tracker ID's (i.e. UA-XXXXXX-X) and return a list of associated entities that have the identified tracker present.

To learn more about RiskIQ Community (PassiveTotal), please visit the [official website](https://community.riskiq.com/).

Check out the integration in action:

![passivetotal](images/overlay.gif)

## RiskIQ Community (PassiveTotal) Requests

| Entity Type | REST API Endpoints Searched |
|------------|-----------------------------|
| IPv4 and Domain | https://api.passivetotal.org/v2/cards/summary <br> https://api.passivetotal.org/v2/enrichment/malware (on details) <br> https://api.passivetotal.org/v2/enrichment/osint (on details)|
| Google Tracker ID's | https://api.passivetotal.org/v2/trackers/search |

## RiskIQ Community (PassiveTotal) Integration Options

### RiskIQ Community (PassiveTotal) API URL
The URL of the RiskIQ Community (PassiveTotal) API including the schema (i.e., https://). Default is set to:  https://api.passivetotal.org

### RiskIQ Community (PassiveTotal) Api Username
PassiveTotal Username, used to access the API.

### RiskIQ Community (PassiveTotal) ApiKey
PassiveTotal API Key

### Number of Associated Records to Return
Total number of associated Malware and OSINT records to return in the Polarity Overlay. Please note the higher the number to longer it will take for the query to return. Default is set to 10.

### Ignore List
List of domains that you never want to send to PassiveTotal.

### Ignore Domain Regex
Domains that match the given regex will not be looked up.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
