import boto3
import json
import logging
import os

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

SLACK_CHANNEL = os.environ['SLACK_WEBHOOK_URL']
logger = logging.getLogger()
logger.setLevel(logging.INFO)




def lambda_handler(event, context):
    
    
    ### log the raw message
    logger.info("Event: " + str(event))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Message: " + str(message))
    alarm_details = json.loads(message['AlarmDescription'])
    logger.info("alarm_details: " + str(alarm_details))

    print(alarm_details)

    ### declare all fields
    timestamp = event['Records'][0]['Sns']['Timestamp']
    alarm_name = message['AlarmName']
    new_state = message['NewStateValue']
    NewStateReason = message['NewStateReason']
    region = message['Region']
    reason = message['NewStateReason']
    details = message['AlarmDescription']
    id = ''
    element = alarm_details['element']
    element_type = alarm_details['element_type']
    element_subtype = alarm_details['element_subtype']
    tags = alarm_details['alert_source']
    alert_source = alarm_details['alert_source']
    state = alarm_details['severity']
    issue = alarm_details['issue']
    supportowner = alarm_details['service_owner']
    severity = alarm_details['severity']
    description = alarm_details['description']
    
    blocks = [		
        {
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "%s: [%s] %s" % (new_state, severity, issue)
			}
		},
		{
			"type": "section",
			"fields": [
				{
					"type": "plain_text",
					"text": """
					   timestamp: %s \n state: %s \n Severity: %s \n element: %s \n element_type: %s \n element_subtype: %s \n alert_source: %s \n supportowner: %s \n description: %s \n site: %s \n reason: %s
					            
					        """ % (timestamp, new_state, severity, element, element_type, element_subtype, alert_source, supportowner, description, region, reason)
				}
			]
		}		
	]



    
    
    
    slack_message = {
        'channel': SLACK_CHANNEL,
        
        'text': details,
        'blocks': json.dumps(blocks) if blocks else None
    }
    req = Request(SLACK_CHANNEL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
