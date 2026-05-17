import json
import boto3
import os
from datetime import datetime

sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')

MITRE_MAPPING = {
    'detect_root_usage': {
        'technique_id': 'T1078',
        'technique_name': 'Valid Accounts',
        'tactic': 'Privilege Escalation',
        'severity': 'CRITICAL'
    },
    'detect_iam_escalation': {
        'technique_id': 'T1484',
        'technique_name': 'Domain Policy Modification',
        'tactic': 'Privilege Escalation / Defense Evasion',
        'severity': 'HIGH'
    },
    'detect_s3_exfil': {
        'technique_id': 'T1537',
        'technique_name': 'Transfer Data to Cloud Account',
        'tactic': 'Exfiltration',
        'severity': 'MEDIUM'
    },
    'detect_cloudtrail_disable': {
        'technique_id': 'T1562',
        'technique_name': 'Impair Defenses',
        'tactic': 'Defense Evasion',
        'severity': 'CRITICAL'
    },
    'detect_new_user_created': {
        'technique_id': 'T1136',
        'technique_name': 'Create Account',