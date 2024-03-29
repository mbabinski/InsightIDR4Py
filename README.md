# InsightIDR4Py
A Python client allowing simplified interaction with Rapid7's InsightIDR REST API.

InsightIDR4Py allows users to perform numerous actions within Rapid7 [InsightIDR](https://docs.rapid7.com/insightidr/). This tool handles some of the challenges and complexities of using the InsightIDR REST API, including polling queries in progress, paginated responses, handling the JSON output, and time range queries.

These capabilities can be particularly useful for automating processes, integrating log data with other APIs (like VirusTotal), managing content in the InsightIDR platform, and performing multi-tenant workflows (for instance, updating content across tenants for consistency, or copying content from one InsightIDR tenant to another). For some ideas on how InsightIDR4Py can be used, check out this [blog post](https://micahbabinski.medium.com/button-pusher-to-masterbuilder-automating-siem-workflows-3f51874a80e) where I cover some use cases.

The API capabilities provided by InsightIDR4Py include:
## Logsearch
* Query Events
* Query Groups

## Saved Queries
* List Saved Queries
* Get a Saved Query
* Create Saved Query
* Replace a Saved Query
* Update a Saved Query
* Delete a Saved Query

## Custom Alerts*
* List Custom Alerts
* Get a Custom Alert
* Create Custom Alert
* Replace a Custom Alert
* Update a Custom Alert
* Delete a Custom Alert

*Only pattern detection alerts are supported currently.

## Investigations
* List Investigations
* Get an Investigation
* Create Investigation
* Close Investigations in Bulk
* List Alerts by Investigation
* List Rapid7 Product Alerts by Investigation
* Update Investigation
* List Comments on an Investigation
* Create Comment
* Delete Comment

## Threats
* Create Threat
* Add Indicators to Threat
* Replace Threat Indicators
* Delete Threat

Happy analyzing :monocle_face: and happy administering! :hammer:

# Installation
InsightIDR4Py is available on [PyPI](https://pypi.org/project/InsightIDR4Py/) and can be installed using:
```
pip install InsightIDR4Py
```

# Prerequisites
You will need obtain an API key from the InsightIDR system. The documentation for this can be found [here](https://docs.rapid7.com/insight/managing-platform-api-keys/). From there, you'll use this API key value to create the InsightIDR API object as shown below:
```python
import InsightIDR4Py as idr

# define API key (store this value securely)
api_key = "API_Key_Here"

# create the InsightIDR object
api = idr.InsightIDR(api_key)
```
Remember to store the API key securely! There are several ways to do this, and you should make sure that the way you choose aligns with your organization's security policy. Python's [keyring](https://pypi.org/project/keyring/) library is one possibility.

# Examples
## Example 1: Query DNS Logs for Suspicious TLDs
```python
import InsightIDR4Py as idr

# create the InsightIDR object
api = idr.InsightIDR(api_key)

# define the query parameters
logset_name = "DNS Query"
query = "where(public_suffix IN [buzz, top, club, work, surf, tw, gq, ml, cf, biz, tk, cam, xyz, bond])"
time_range = "Last 36 Hours"

# query the logs
events = api.QueryEvents(logset_name, query, time_range)

# print out an event
print(event[0])
```
Result:
```python
{'timestamp': '2021-09-28T15:11:45.000Z', 'asset': 'windesk05.organization.com', 'source_address': '192.168.4.10', 'query': 'regulationprivilegescan.top', 'public_suffix': 'top', 'top_private_domain': 'regulationprivilegescan.top', 'query_type': 'A', 'source_data': '09/28/2021 8:11:45 AM 1480 PACKET  00000076ED1A0140 UDP Rcv 192.168.4.121   c3b3   Q [0001   D   NOERROR] A      (3)regulationprivilegescan(3)top(0)'}
```

## Example 2: Query Authentication Logs for top Five Failed Logins, Grouped by Count
```python
import InsightIDR4Py as idr

# create the InsightIDR object
api = idr.InsightIDR(api_key)

# define the query parameters
logset_name = "Asset Authentication"
query = "where(source_json.eventCode = 4625) groupby(destination_account) limit(5)"
time_range = "Last 24 Hours"

# query the logs
groups = api.QueryGroups(logset_name, query, time_range)

# print out the groups
for group in groups.items():
    print(group)
```
Result:
```
('Mark.Corrigan', 132)
('Jeremy.Usborne', 102)
('Sophie.Chapman', 88)
('Alan.Johnson', 64)
('Super.Hans', 24)
```

## Example 3: Query VPN Logins from a Certain IP Range and Check the Results Using [AbuseIPDB](https://www.abuseipdb.com/)
This example uses [python-abuseipdb](https://github.com/meatyite/python-abuseipdb), a Python object oriented wrapper for AbuseIPDB v2 API. 

It requires an API key, which you can get by creating a free account. From there, go to User Account > API, choose Create Key, and enter this string into the abuse_ip_db_api_key variable in the example below.

The same API key security principles mentioned above apply here. Guard your API keys to prevent rogue usage!

```python
import InsightIDR4Py as idr
import abuseipdb import *

# create the InsightIDR object
api = idr.InsightIDR(api_key)

# define the AbuseIPDB API key
abuse_ip_db_api_key = "YOUR_KEY_HERE"

# define the query parameters
logset_name = "Ingress Authentication"
query = "where(service = vpn AND source_ip = IP(64.62.128.0/17))"
time_range = "Last 24 Hours"

# query the logs
events = api.QueryEvents(logset_name, query, time_range)

# check the source IP addresses in AbuseIPDB and display results
if len(events) > 0:
    ipdb = AbuseIPDB(abuse_ip_db_api_key)
    for event in events:
	check = ipdb.check(event["source_ip"])
	print("----------")
	print("IP Address: " + ip_check.ipAddress)
	print("Last reported at: " + ip_check.lastReportedAt)
	print("Abuse confidence score: " + str(ip_check.abuseConfidenceScore))
	print("Abuser country: " + ip_check.countryName)
	print("Abuser ISP: " + ip_check.isp)
	print("Total reports of abuser: " + str(ip_check.totalReports))
	print("----------")
```

# License
This repository is licensed under an [MIT license](https://github.com/mbabinski/InsightIDR4Py/blob/main/LICENSE), which grants extensive permission to use this material however you wish.

# Contributing
You are welcome to contribute however you wish! I appreciate feedback in any format.