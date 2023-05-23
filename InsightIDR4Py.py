import requests, json, time
from datetime import datetime, timedelta, timezone

def GetDefaultStartTime():
    """
    Get default start time for time-based queries.
    """
    default_start_time = (datetime.now(timezone.utc) - timedelta(28)).strftime("%Y-%m-%dT%H:%M:%SZ")

    return default_start_time

def GetDefaultEndTime():
    """
    Get default end time (now) for time-based queries.
    """
    default_end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return default_end_time

class InsightIDR(object):
    def __init__(self, api_key, region=None):
        self.session = requests.Session()
        self.session.headers = {"X-Api-Key": api_key}
        if not region:
            self.region = self._get_region()
        else:
            self.region = region
        self.logs_url = "https://{}.rest.logs.insight.rapid7.com/query/logs/".format(self.region)
        self.query_url = "https://{}.rest.logs.insight.rapid7.com/query/".format(self.region)
        self.log_mgmt_url = "https://{}.api.insight.rapid7.com/log_search/management/logs/".format(self.region)
        self.investigations_url = "https://{}.api.insight.rapid7.com/idr/v2/investigations/".format(self.region)
        self.comments_url = "https://{}.api.insight.rapid7.com/idr/v1/comments/".format(self.region)
        self.threat_url = "https://{}.api.insight.rapid7.com/idr/v1/customthreats/".format(self.region)

    def _get_region(self):
        """
        This method cycles through available API regions, making a call to the log management URL with each
        region until a successful call indicates the correct region. If you already know your region, simply
        pass that in when creating the InsightIDR object.
        """
        self.regions = ["us", "us2", "us3", "eu", "ca", "au", "ap"]
        for region in self.regions:
            self.response = self.session.get("https://{}.rest.logs.insight.rapid7.com/management/logs".format(region))
            if self.response.status_code == 200:
                return region
      
    def GetLogInfo(self):
        """Returns metadata about the available log sources."""
        response = self.session.get(self.log_mgmt_url).json()["logs"]
        
        return response

    def ListLogSetNames(self):
        """Returns a list of logset names as they appear in the InsightIDR console."""
        log_info = self.GetLogInfo()
        logset_names = list(set([log["logsets_info"][0]["name"] for log in log_info]))

        return sorted(logset_names)

    def ListLogIdsByLogSetName(self, logset_name):
        """Returns a list of log ID values for a given logset name."""
        log_info = self.GetLogInfo()
        log_ids = [log["id"] for log in log_info if log["logsets_info"][0]["name"].upper() == logset_name.upper()]

        return log_ids

    def QueryEvents(self, logset_name, query, time_range="Last 20 Minutes", from_time=None, to_time=None, suppress_msgs=True):
        """
        Returns an ordered list of events matching a given timeframe, logset name, and query. Must supply
        either a relative time range or from time and to time in the format MM/DD/YYYY Hr:Min:Sec.
        """
        # convert from/to times as necessary (string to timestamp with milliseconds)
        if not time_range:
            from_time = int(datetime.strptime(from_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000
            to_time = int(datetime.strptime(to_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000

        # get the relevant Log IDs
        log_ids = self.ListLogIdsByLogSetName(logset_name)
        # get the time range
        if time_range:
            during = {"time_range": time_range}
        else:
            during = {"from": from_time, "to": to_time}
        body = {"logs": log_ids,
                "leql": {"during": during,
                         "statement": query}}

        # build the first full URL
        url = self.logs_url + "?per_page=500"

        # retrieve the data
        run = True
        events = []
        cntr = 1
        r = self.session.post(url, json=body)
        while run:
            if r.status_code == 202:
                cont = True
                while cont:
                    continue_url = r.json()["links"][0]["href"]
                    r = self.session.get(continue_url, headers=headers)
                    if r.status_code != 202:
                        cont = False
                        break
            elif r.status_code == 200:
                events.extend(r.json()["events"])
                if "links" in r.json():
                    continue_url = r.json()["links"][0]["href"]
                    r = self.session.get(continue_url, headers=headers)
                else:
                    run = False
            else:
                raise ValueError("Query failed without a normal status code. Status code returned was: " + str(r.status_code))
                return
            cntr += 1
            if not suppress_msgs:
                if cntr % 30 == 0:
                    print("-Gathered {} events.".format(str(len(events))))

        # filter the event objects to get just the dictionary representation of the event data
        events = [json.loads(event["message"]) for event in events]

        return events

    def QueryGroups(self, logset_name, query, time_range="Last 20 Minutes", from_time=None, to_time=None, suppress_msgs=True):
        """
        Retrieves group values and associated stats. Query must contain a groupby() clause
        """
        # validate input query
        if not "groupby(" in query.lower():
            raise ValueError("Query must contain the groupby() clause!")
        
        # convert from/to times as necessary (string to timestamp with milliseconds)
        if not time_range:
            from_time = int(datetime.strptime(from_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000
            to_time = int(datetime.strptime(to_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000

        # get the relevant Log IDs
        log_ids = self.ListLogIdsByLogSetName(logset_name)

        # get the time range
        if time_range:
            during = {"time_range": time_range}
        else:
            during = {"from": from_time, "to": to_time}
        body = {"logs": log_ids,
                "leql": {"during": during,
                         "statement": query}}

        # build the first full URL
        url = self.logs_url

        # retrieve the data
        run = True
        results = []
        cntr = 1
        r = self.session.post(url, json=body)
        while run:
            if r.status_code == 202:
                cont = True
                while cont:
                    continue_url = r.json()["links"][0]["href"]
                    r = self.session.get(continue_url)
                    if r.status_code != 202:
                        cont = False
                        break
            elif r.status_code == 200:
                if "links" in r.json():
                    continue_url = r.json()["links"][0]["href"]
                    r = self.session.get(continue_url)
                else:
                    results.extend(r.json()["statistics"]["groups"])
                    run = False
            else:
                raise ValueError("Query failed without a normal status code. Status code returned was: " + str(r.status_code))
                return
            cntr += 1
            if not suppress_msgs:
                if cntr % 30 == 0:
                    print("-Gathered {} groups.".format(str(len(results))))

        groups = {}
        for result in results:
            key = list(result.keys())[0]
            value = int(result[key]["count"])
            groups[key] = value

        return groups

    def ListInvestigations(self,
                           assignee_email=None,
                           start_time=GetDefaultStartTime(),
                           end_time=GetDefaultEndTime(),
                           multi_customer=False,
                           priorities=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                           sort="priority,DESC",
                           sources=None,
                           statuses=["OPEN", "INVESTIGATING", "CLOSED"],
                           tags=None):
        """
        Queries InsightIDR investigations based on available filter criteria.
        """
        # list to hold investigations
        investigations = []
        # pre-process parameters
        priorities = ", ".join(priorities)
        statuses = ",".join(statuses)
        if tags:
            tags = ", ".join(tags)
        params = {
            "index": 0,
            "size": 100,
            "assignee.email": assignee_email,
            "start_time": start_time,
            "end_time": end_time,
            "multi-customer": multi_customer,
            "priorities": priorities,
            "sort": sort,
            "sources": sources,
            "statuses": statuses,
            "tags": tags
        }
        # filter the parameters to be only those with a supplied value
        params = {key:val for key, val in params.items() if val}
        # get the initial set of investigations
        url = self.investigations_url
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.get(url, params=params)
        result = response.json()
        # get the total
        total = result["metadata"]["total_data"]
        # add the results to the output list
        investigations.extend(result["data"])
        # iterate through remaining investigations and add them to the output list
        while len(investigations) < total:
            params["index"] += 100
            response = self.session.get(url, params)
            result = response.json()
            investigations.extend(result["data"])

        # return the result
        return investigations

    def GetInvestigation(self, investigation_id, multi_customer=False):
        """
        Retrieves a single investigation by Investigation ID/RRN
        """
        url = self.investigations_url + "{}".format(investigation_id)
        params = {"multi-customer": multi_customer}
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.get(url, params=params)
        result = response.json()

        return result
        
    def CreateInvestigation(self, title, assignee_email=None, disposition="UNDECIDED",
                            priority="LOW", status="OPEN"):
        """
        Creates an InsightIDR investigation.
        """
        if assignee_email:
            assignee = {"email": assignee_email}
        else:
            assignee = None
        data = {
            "title": title,
            "assignee": assignee,
            "disposition": disposition,
            "priority": priority,
            "status": status
        }
        # filter the parameters to be only those with a supplied value
        data = {key:val for key, val in data.items() if val}

        # submit the request
        url = self.investigations_url
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.post(url, json=data)
        result = response.json()

        return result

    def CloseInvestigationsInBulk(self, source, from_time=GetDefaultStartTime(),
                                  to_time=GetDefaultEndTime(), alert_type=None,
                                  disposition=None, detection_rule_rrn=None,
                                  max_investigations_to_close=None):
        """
        Closes investigations in bulk according to selected criteria.
        """
        data = {
            "source": source.upper(),
            "from": from_time,
            "to": to_time,
            "alert_type": alert_type,
            "disposition": disposition,
            "detection_rule_rrn": detection_rule_rrn,
            "max_investigations_to_close": max_investigations_to_close
        }

        # validate input
        if source.upper() not in ("ALERT", "MANUAL", "HUNT"):
            raise ValueError("Source must be one of [ALERT, MANUAL, or HUNT]!")
        if source.upper() == "ALERT" and not alert_type:
            raise ValueError("The alert_type parameter is required when source is ALERT!")
        if detection_rule_rrn and alert_type != "Attacker Behavior Detected":
            raise ValueError("If a detection rule RRN is specified, the alert type must be 'Attacker Behavior Detected'")

        # filter the parameters to be only those with a supplied value
        data = {key:val for key, val in data.items() if val}

        # submit the request
        url = self.investigations_url + "bulk_close"
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.post(url, json=data)
        result = response.json()

        return result

    def ListAlertsByInvestigation(self, investigation_id, multi_customer=False):
        """
        Retrieves all alerts associated with an investigation. The listed alerts are sorted in descending order by alert create time.
        """
        alerts = []
        url = self.investigations_url + "{}/alerts".format(investigation_id)
        params = {
            "index": 0,
            "size": 100,
            "multi-customer": multi_customer
        }
        # make initial request
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.get(url, params=params)
        result = response.json()
        # get the total
        total = result["metadata"]["total_data"]
        # add the results to the output list
        alerts.extend(result["data"])
        # iterate through remaining alerts and add them to the output list
        while len(alerts) < total:
            params["index"] += 100
            response = self.session.get(url, params)
            result = response.json()
            alerts.extend(result["data"])

        return alerts

    def ListRapid7ProductAlertsByInvestigation(self, investigation_id, multi_customer=False):
        """
        Retrieves all Rapid7 product alerts associated with an investigation. These alerts are generated by Rapid7 products other
        than InsightIDR that you have an active license for.
        """
        product_alerts = []
        url = self.investigations_url + "{}/rapid7-product-alerts".format(investigation_id)
        params = {"multi-customer": multi_customer}
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.get(url, params=params)
        result = response.json()

        return result

    def UpdateInvestigation(self, investigation_id, multi_customer=False, assignee_email=None, disposition=None, priority=None,
                            status=None, threat_command_close_reason=None, threat_command_free_text=None, title=None):
        """
        Updates multiple fields in a single operation for an investigation, specified by id or rrn.
        The investigation will be returned with its changed fields. Null or omitted fields will not have their values
        updated in the investigation.
        """
        if assignee_email:
            assignee = {"email": assignee_email}
        else:
            assignee = None
        params = {"multi-customer": multi_customer}
        data = {
            "title": title,
            "assignee": assignee,
            "disposition": disposition,
            "priority": priority,
            "status": status,
            "threat_command_close_reason": threat_command_close_reason,
            "threat_command_free_text": threat_command_free_text
        }
        # submit the request
        url = self.investigations_url + investigation_id
        self.session.headers["Accept-version"] = "investigations-preview"
        response = self.session.patch(url, json=data, params=params)
        result = response.json()

        return result

    def ListCommentsByInvestigation(self, investigation_rrn):
        """
        Returns a list of comments filtered by a specific investigation with a given rrn.
        """
        comments = []
        url = self.comments_url
        params = {
            "index": 0,
            "size": 100,
            "target": investigation_rrn
        }
        
        # make initial request
        self.session.headers["Accept-version"] = "comments-preview"
        response = self.session.get(url, params=params)
        result = response.json()
        # get the total
        total = result["metadata"]["total_data"]
        # add the results to the output list
        comments.extend(result["data"])
        # iterate through remaining alerts and add them to the output list
        while len(comments) < total:
            params["index"] += 100
            response = self.session.get(url, params)
            result = response.json()
            comments.extend(result["data"])

        return comments

    def CreateComment(self, investigation_rrn, comment_text):
        """
        Creates a comment on an investigation.
        """
        data = {
            "attachments": [], # attachments not yet supported
            "body": comment_text,
            "target": investigation_rrn
        }
        url = self.comments_url
        self.session.headers["Accept-version"] = "comments-preview"
        response = self.session.post(url, json=data)
        result = response.json()

        return result

    def DeleteComment(self, comment_rrn):
        """
        Deletes a comment identified by its rrn value.
        """
        url = self.comments_url + "{}".format(comment_rrn)
        response = self.session.delete(url)

        return response

    def CreateThreat(self, threat_name, threat_description, indicators={}):
        """
        CreateS a private InsightIDR Community Threat and optionally adds indicators to this Community Threat.
        Indicator types can include IP addresses, hashes, domain names, or URLs.
        """
        data = {
            "threat": threat_name,
            "note": threat_description,
            "indicators": indicators,
        }
        url = self.threat_url
        response = self.session.post(url, json=data)
        result = response.json()

        return result

    def AddIndicatorsToThreat(self, threat_key, ips=None, domains=None, hashes=None, urls=None):
        """
        Adds indicators to a threat based off threat key. The threat key can be obtained on the threat page in the InsightIDR GUI.
        Only JSON formatted indicators are supported at this time.
        """
        params = {"format": "json"}
        data = {}
        if ips:
            data["ips"] = ips
        if domains:
            data["domain_names"] = domains
        if hashes:
            data["hashes"] = hashes
        if urls:
            data["urls"] = urls
        url = self.threat_url + "key/{}/indicators/add".format(threat_key)

        response = self.session.post(url, params=params, json=data)
        result = response.json()

        return result

    def ReplaceThreatIndicators(self, threat_key, ips=None, domains=None, hashes=None, urls=None):
        """
        Replaces indicators in a threat abased off threat key. The threat key can be obtained on the threat page in the InsightIDR GUI.
        Only JSON formatted indicators are supported at this time.
        """
        params = {"format": "json"}
        data = {}
        if ips:
            data["ips"] = ips
        if domains:
            data["domain_names"] = domains
        if hashes:
            data["hashes"] = hashes
        if urls:
            data["urls"] = urls
        url = self.threat_url + "key/{}/indicators/replace".format(threat_key)

        response = self.session.post(url, params=params, json=data)
        result = response.json()

        return result

    def DeleteThreat(self, threat_key, reason=""):
        """
        Deletes an InsightIDR Community Threat. The threat key can be obtained on the threat page in the InsightIDR GUI.
        """
        data = {"reason": reason}
        url = self.threat_url + "/key/{}/delete".format(threat_key)
        response = self.session.post(url, json=data)
        result = response.json()

        return result
        
        
    def ListSavedQueries(self):
        """
        Lists saved queries in the InsightIDR platform.
        """
        url = self.query_url + "saved_queries"
        response = self.session.get(url)
        result = response.json()
        queries = result["saved_queries"]

        return queries

    def GetSavedQuery(self, saved_query_id):
        """
        Retrieve details on a single saved query.
        """
        url = self.query_url + "saved_queries/{}".format(saved_query_id)
        response = self.session.get(url)
        result = response.json()["saved_query"]

        return result

    def CreateSavedQuery(self, name, query, logset_name=None, time_range="Last 20 Minutes", from_time=None, to_time=None):
        """
        Creates a Saved Query.
        """
        # convert from/to times as necessary (string to timestamp with milliseconds)
        if not time_range:
            from_time = int(datetime.strptime(from_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000
            to_time = int(datetime.strptime(to_time, "%m/%d/%Y %H:%M:%S").timestamp()) * 1000

        # get the relevant Log IDs
        if logset_name:
            log_ids = self.ListLogIdsByLogSetName(logset_name)
        else:
            log_ids = []
        
        # get the time range
        if time_range:
            during = {"time_range": time_range}
        else:
            during = {"from": from_time, "to": to_time}

        data = {
            "saved_query": {
                "name": name,
                "leql": {
                    "statement": query,
                    "during": during
                    },
                "logs": log_ids
                }
            }

        # make the reuest
        url = self.query_url + "saved_queries"
        response = self.session.post(url, json=data)
        result = response.json()

        return result

    def ReplaceSavedQuery(self, saved_query_id, name, query, logset_name=None, time_range=None, from_time=None, to_time=None):
        """
        Replace an existing saved query with the parameters specified in the input.
        """
        # get the relevant Log IDs (updated or keep as existing if not set)
        if logset_name:
            log_ids = self.ListLogIdsByLogSetName(logset_name)
        else:
            query_obj = self.GetSavedQuery(saved_query_id)
            log_ids = query_obj["logs"]
        
        # get the time range
        if time_range:
            during = {"time_range": time_range}
        elif from_time and to_time:
            during = {"from": from_time, "to": to_time}
        else:
            during = None

        data = {
            "saved_query": {
                "name": name,
                "leql": {
                    "statement": query,
                    "during": during
                    },
                "logs": log_ids
                }
            }

        # make the reuest
        url = self.query_url + "saved_queries/{}".format(saved_query_id)
        response = self.session.put(url, json=data)
        result = response.json()

        return result

    def UpdateSavedQuery(self, saved_query_id, name=None, query=None, logset_name=None, time_range=None, from_time=None, to_time=None):
        """
        Update an existing saved query with the parameters specified in the input.
        """
        # get the relevant Log IDs
        if logset_name:
            log_ids = self.ListLogIdsByLogSetName(logset_name)
        else:
            query_obj = self.GetSavedQuery(saved_query_id)
            log_ids = query_obj["logs"]
        
        # get the time range
        if time_range:
            during = {"time_range": time_range}
        elif from_time and to_time:
            during = {"from": from_time, "to": to_time}
        else:
            during = None

        data = {
            "saved_query": {
                "name": name,
                "leql": {
                    "statement": query,
                    "during": during
                    },
                "logs": log_ids
                }
            }

        # make the reuest
        url = self.query_url + "saved_queries/{}".format(saved_query_id)
        response = self.session.patch(url, json=data)
        result = response.json()

        return result

    def DeleteSavedQuery(self, saved_query_id):
        """
        Delete a saved query with the specified saved query ID.
        """
        url = self.query_url + "saved_queries/{}".format(saved_query_id)
        response = self.session.delete(url)

        return response
