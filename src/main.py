import json
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


SARIF_DATA = os.getenv("SARIF_DATA")
PRINT_RESULTS = os.getenv("PRINT_RESULTS", False)
SEVERITY_CUTOFF_NUM = os.getenv("SEVERITY_CUTOFF_NUM")
SLACK_TOKEN = os.environ['SLACK_TOKEN']
GITHUB_RUN_URL = os.getenv("GITHUB_RUN_URL")
REPORT_NAME = os.getenv("REPORT_NAME")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL")


def generate_rule_dictionary(rules):
    # Creates a dictionary of anchore alerts (aka rules) and
    # their associated severities. Severities are floats. 
    # 0.0 - 5.0: low
    # 5.1 - 7.0: medium
    # 7.1 - 9: high
    # 9.1 - 10.10: critical
    rule_dictionary = {}

    for rule in rules:
        rule_id = rule.get("id")
        severity = rule["properties"].get("security-severity", "Not Found")
        if rule_id:
            rule_dictionary[rule_id.lower()] = severity

    return rule_dictionary


def parse_results(results, rule_dictionary):
    severity_counter = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    with open ("job_summary.md", "w") as f:
        f.write("# Anchore Scan Results\n")
        f.write("")
        f.write("| Severity | Rule ID  | Location | Description | \n")
        f.write("| ------ | ------ | ------ | ------ | \n")
        
        for result in results:
            rule_id = result["ruleId"]
            severity_number = float(rule_dictionary[rule_id.lower()])

            severity_category = ""

            if severity_number in range(0, 5):
                severity_category = "low"
            elif severity_number in range(5, 8):
                severity_category = "medium"
            elif severity_number in range(8, 9):
                severity_category = "high"
            elif severity_number in range(9, 11):
                severity_category = "critical"

            severity_counter[severity_category] = severity_counter.get(severity_category, 0) + 1

            if severity_number >= float(SEVERITY_CUTOFF_NUM):
                description = result["message"]["text"]
                locations = result["locations"]

                for location in locations:
                    logical_locations = location["logicalLocations"]
                    for logical_locatation in logical_locations:
                        name = logical_locatation["fullyQualifiedName"]

                        if PRINT_RESULTS:
                            print("###########################################")
                            print("Rule ID: {}".format(rule_id))
                            print("Vulnerability Number: {}".format(severity_number))
                            print("Vulnerability Category: {}".format(severity_category))
                            print("Description: {}".format(description))
                            print("Locations:")
                            print(name)
                            print("###########################################")
                            print()
                        
                        f.write("| {} | {} | {} | {} |\n".format(
                            rule_dictionary[rule_id.lower()], rule_id, name, description
                        ))
    
    return severity_counter


def create_job_summary():
    with open(os.path.abspath("job_summary.md"), "r")  as fr:
        os.environ["GITHUB_STEP_SUMMARY"] = fr.read()
        
    print("Job summary report created {}".format(os.path.abspath("job_summary.md")))   
    
    
def send_report(severity_counter):
    print("truncated slack token is {}".format(SLACK_TOKEN[:4]))
    client = WebClient(token=SLACK_TOKEN)

    try:
        _ = client.chat_postMessage(
            channel=SLACK_CHANNEL,
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Anchore scan results for {}\n <{}|View> Github actions run URL".format(REPORT_NAME, GITHUB_RUN_URL)
                    }
                },
                {
			        "type": "divider"
		        },
                {
                   "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":alert: {} Critical Vulnerabilities".format(severity_counter["critical"])
                    } 
                },
                {
                   "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":red_circle: {} High Vulnerabilities".format(severity_counter["high"])
                    } 
                },
                {
                   "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":yellow-circle: {} Medium Vulnerabilities".format(severity_counter["medium"])
                    } 
                },
                {
                   "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":large_blue_circle: {} Low Vulnerabilities".format(severity_counter["low"])
                    } 
                }
            ]
        )
    except SlackApiError as e:
        print(f"Got a slack error: {e.response['error']}")


def main():
    print("This is sarif data {}".format(SARIF_DATA))
    with open(SARIF_DATA, "r") as f:
        data = json.load(f)
    
    for run in data.get("runs"):
        results = run["results"]
        rules = run["tool"]["driver"]["rules"]

    rule_dictionary = generate_rule_dictionary(rules)
    severity_counter = parse_results(results, rule_dictionary)
    create_job_summary()
    send_report(severity_counter)

    
if __name__ == "__main__":
    main()