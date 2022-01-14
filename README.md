# InsightIDR4Py
Allows simplified Python interaction with Rapid7's InsightIDR REST API.

InsightIDR4Py allows analysts to query log data from Rapid7 [InsightIDR](https://docs.rapid7.com/insightidr/), analyze it within Python, and/or feed it to other APIs like VirusTotal, AbuseIPDB, or others. This tool handles some of the challenges and complexities of using the InsightIDR REST API, including polling queries in progress, paginated responses, handling the JSON output, and time range queries.

Happy analyzing!:monocle_face:

# Prerequisites
You will need obtain an API key from the InsightIDR system. The documentation for this can be found [here](https://docs.rapid7.com/insight/managing-platform-api-keys/). From there, you'll need to pass this value to the API key variable shown below:
```python
# define API key and headers (remember to store your API keys securely!)
api_key = "API_Key_Here"
```
There are several ways to do this, and you should make sure that the way you choose aligns with your organization's security policy. Python's [keyring](https://pypi.org/project/keyring/) library is one possibility.

# Examples
## Example 1: Query DNS Logs for Suspicious TLDs
```python
import InsightIDR4Py as idr

# define the query parameters
logset_name = "DNS Query"
query = "where(public_suffix IN [buzz, top, club, work, surf, tw, gq, ml, cf, biz, tk, cam, xyz, bond])"
time_range = "Last 36 Hours"

# query the logs
events = idr.QueryEvents(logset_name, query, time_range)

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

# define the query parameters
logset_name = "Asset Authentication"
query = "where(source_json.eventCode = 4625) groupby(destination_account) limit(5)"
time_range = "Last 24 Hours"

# query the logs
groups = idr.QueryGroups(logset_name, query, time_range)

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

# define the AbuseIPDB API key
abuse_ip_db_api_key = "YOUR_KEY_HERE"

# define the query parameters
logset_name = "Ingress Authentication"
query = "where(service = vpn AND source_ip = IP(64.62.128.0/17))"
time_range = "Last 24 Hours"

# query the logs
events = idr.QueryEvents(logset_name, query, time_range)

# print out an event
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

