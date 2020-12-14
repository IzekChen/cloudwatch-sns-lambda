import boto3
import json
import logging
import os
from alert_mapping import alert_mapping

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

SLACK_CHANNEL = os.environ['SLACK_WEBHOOK_URL']
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

DEFAULT_USERNAME = 'AWS Lambda'
DEFAULT_CHANNEL = os.environ['SLACK_WEBHOOK_URL']

def get_slack_username(alert_source):
    '''Map event source to the Slack username
    '''
    username_map = {
        'cloudwatch': 'AWS CloudWatch',
        'autoscaling': 'AWS AutoScaling',
        'elasticache': 'AWS ElastiCache',
        'rds': 'AWS RDS'}

    try:
        return username_map[alert_source]
    except KeyError:
        return DEFAULT_USERNAME

def get_slack_emoji(alert_source, topic_name, NewStateValue='default'):
    '''Map an event source, severity, and condition to an emoji
    '''
    emoji_map = {
        'autoscaling': {
            'notices': {'default': ':scales:'}},
        'cloudwatch': {
            'notices': {
                'ok': ':ok:',
                'alarm': ':fire:',
                'insuffcient_data': ':question:'},
            'alerts': {
                'ok': ':ok:',
                'alarm': ':fire:',
                'insuffcient_data': ':question:'}},
        'cloudwatch ML': {
            'notices': {
                'ok': ':ok:',
                'alarm': ':fire:',
                'insuffcient_data': ':question:'},
            'alerts': {
                'ok': ':ok:',
                'alarm': ':fire:',
                'insuffcient_data': ':question:'}},
        'elasticache': {
            'notices': {'default': ':stopwatch:'}},
        'rds': {
            'notices': {'default': ':registered:'}}}
    try:
        return emoji_map[alert_source][topic_name][NewStateValue]
    except KeyError:
        if topic_name == 'alerts':
            return ':fire:'
        else:
            return ':information_source:'

def lambda_handler(event, context):
    ### log the raw message
    logger.info("Event: " + str(event))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Message: " + str(message))
    alarm_details = json.loads(message['AlarmDescription'])
    logger.info("alarm_details: " + str(alarm_details))

    print(event)

    ### declare all fields
    try:
        sns = event['Records'][0]['Sns']
    except Exception as e:
        logger.error("Request failed: %d %s", e.code, e.reason)

    if message:
        alarm_name = message['AlarmName']
        new_state = message['NewStateValue']
        NewStateReason = message['NewStateReason']
        region = message['Region']
        reason = message['NewStateReason']
        details = message['AlarmDescription']
        threshold = message['Trigger']['Threshold']

    if alarm_details != '':
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

    if sns:
        if sns['Subject']:
            subject = sns['Subject']
        else:
            message = sns['Message']
    
    alert_id = alert_source + '-' + element + '-' + element_type

    if message.get('AlarmName'):
        NewStateValue = message['NewStateValue']
        color_map = {
            'OK': 'good',
            'INSUFFICIENT_DATA': 'warning',
            'ALARM': 'danger'
        }     
        attachments = [{
            "mrkdwn_in": ["text"],
            'fallback': message,
            'message': message,
            'color': color_map[NewStateValue],
            'title': message['AlarmName'],
            "title_link": alert_mapping[alert_id], 
            "fields": [{
                "title": "Status",
                "value": '`' + message['NewStateValue'] + '`',
                "short": True
            }, {
                "title": "Severity",
                "value": '`' + severity +'`',
                "short": True
            }, {
                "title": "Source",
                "value": '`' + alert_source + '`',
                "short": True
            }, {
                "title": "Support Owner",
                "value": '`' + supportowner + '`',
                "short": True
            }, {
                "title": "element",
                "value": '`' + element + '`',
                "short": True
            }, {
                "title": "element_subtype",
                "value": '`' + element_subtype + '`',
                "short": True
            }, {
                "title": "Threshold",
                "value": '`' + str(threshold) + '`',
                "short": True
            }, {
                "title": "Description",
                "value": description,
                "short": False
            }, {
                "title": "Reason",
                "value": '```' + message['NewStateReason'] + '```',
                "short": False
            }
            ],
            "thumb_url": "https://s3-eu-west-1.amazonaws.com/tpd/logos/553e07220000ff00057f076a/0x0.png",
            "footer": "footer",
            "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png"
        }]        


    
    topic_name = sns['TopicArn'].split(':')[-1]
    print(topic_name)
    
    
    slack_message = {
        'channel': SLACK_CHANNEL,
        'test': subject,
        'username': get_slack_username(alert_source),
        'icon_emoji': get_slack_emoji(alert_source, topic_name, NewStateReason.lower())
    }
    
    if attachments:
        slack_message['attachments'] = attachments
    print('DEBUG:', slack_message)
    req = Request(SLACK_CHANNEL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
