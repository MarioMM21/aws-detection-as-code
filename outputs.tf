output "sns_topic_arn" {
  description = "ARN of the detection alerts SNS topic"
  value       = aws_sns_topic.detection_alerts.arn
}

output "lambda_function_arn" {
  description = "ARN of the detection handler Lambda"
  value       = aws_lambda_function.detection_handler.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for detection pipeline"
  value       = aws_cloudwatch_log_group.detection_logs.name
}

output "detection_rules_deployed" {
  description = "Number of detection rules deployed"
  value       = "5 MITRE ATT&CK mapped detection rules active"
}

output "mitre_techniques_covered" {
  description = "MITRE ATT&CK techniques covered"
  value = [
    "T1078 - Valid Accounts (Root Usage)",
    "T1484 - Domain Policy Modification (IAM Escalation)",
    "T1537 - Transfer Data to Cloud Account (S3 Exfiltration)",
    "T1562 - Impair Defenses (CloudTrail Disable)",
    "T1136 - Create Account (New IAM User)"
  ]
}