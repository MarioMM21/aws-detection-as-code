terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

data "archive_file" "detection_handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/detection_handler.py"
  output_path = "${path.module}/lambda/detection_handler.zip"
}

resource "aws_sns_topic" "detection_alerts" {
  name = "${var.project_name}-alerts"
  tags = {
    Name        = "Detection Engineering Alerts"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.detection_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_iam_role" "detection_lambda_role" {
  name = "${var.project_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "detection_lambda_policy" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.detection_lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.detection_alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "detection_logs" {
  name              = "/detection-as-code/pipeline"
  retention_in_days = 30
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lambda_function" "detection_handler" {
  filename         = data.archive_file.detection_handler.output_path
  function_name    = "${var.project_name}-handler"
  role             = aws_iam_role.detection_lambda_role.arn
  handler          = "detection_handler.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.detection_handler.output_base64sha256
  timeout          = 30
  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.detection_alerts.arn
    }
  }
  tags = {
    Name        = "Detection Engineering Handler"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_metric_filter" "detect_root_usage" {
  name           = "detect-root-usage"
  log_group_name = aws_cloudwatch_log_group.detection_logs.name
  pattern        = "{ ($.userIdentity.type = Root) && ($.eventType = AwsApiCall) }"
  depends_on     = [aws_cloudwatch_log_group.detection_logs]
  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "DetectionEngineering/MITRE"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "detect_iam_escalation" {
  name           = "detect-iam-escalation"
  log_group_name = aws_cloudwatch_log_group.detection_logs.name
  pattern        = "{ ($.eventSource = iam.amazonaws.com) && (($.eventName = PutUserPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = CreatePolicy)) }"
  depends_on     = [aws_cloudwatch_log_group.detection_logs]
  metric_transformation {
    name          = "IAMPolicyModification"
    namespace     = "DetectionEngineering/MITRE"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "detect_s3_exfil" {
  name           = "detect-s3-exfil"
  log_group_name = aws_cloudwatch_log_group.detection_logs.name
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = GetObject) || ($.eventName = ListBucket) || ($.eventName = GetBucketAcl)) && ($.userIdentity.type != Service) }"
  depends_on     = [aws_cloudwatch_log_group.detection_logs]
  metric_transformation {
    name          = "S3SuspiciousAccess"
    namespace     = "DetectionEngineering/MITRE"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "detect_cloudtrail_disable" {
  name           = "detect-cloudtrail-disable"
  log_group_name = aws_cloudwatch_log_group.detection_logs.name
  pattern        = "{ ($.eventSource = cloudtrail.amazonaws.com) && (($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail)) }"
  depends_on     = [aws_cloudwatch_log_group.detection_logs]
  metric_transformation {
    name          = "CloudTrailDisabled"
    namespace     = "DetectionEngineering/MITRE"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "detect_new_user_created" {
  name           = "detect-new-user-created"
  log_group_name = aws_cloudwatch_log_group.detection_logs.name
  pattern        = "{ ($.eventSource = iam.amazonaws.com) && ($.eventName = CreateUser) }"
  depends_on     = [aws_cloudwatch_log_group.detection_logs]
  metric_transformation {
    name          = "NewIAMUserCreated"
    namespace     = "DetectionEngineering/MITRE"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_root_usage" {
  alarm_name          = "detect-root-usage-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "DetectionEngineering/MITRE"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CRITICAL - T1078 - Root account API call detected"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.detection_alerts.arn]
  tags = {
    MITRETechnique = "T1078"
    Severity       = "CRITICAL"
    Project        = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_iam_escalation" {
  alarm_name          = "detect-iam-escalation-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IAMPolicyModification"
  namespace           = "DetectionEngineering/MITRE"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "HIGH - T1484 - IAM policy modification detected"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.detection_alerts.arn]
  tags = {
    MITRETechnique = "T1484"
    Severity       = "HIGH"
    Project        = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_s3_exfil" {
  alarm_name          = "detect-s3-exfil-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "S3SuspiciousAccess"
  namespace           = "DetectionEngineering/MITRE"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "MEDIUM - T1537 - Suspicious S3 access pattern detected"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.detection_alerts.arn]
  tags = {
    MITRETechnique = "T1537"
    Severity       = "MEDIUM"
    Project        = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_cloudtrail_disable" {
  alarm_name          = "detect-cloudtrail-disable-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "CloudTrailDisabled"
  namespace           = "DetectionEngineering/MITRE"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CRITICAL - T1562 - CloudTrail logging disabled"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.detection_alerts.arn]
  tags = {
    MITRETechnique = "T1562"
    Severity       = "CRITICAL"
    Project        = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_new_user_created" {
  alarm_name          = "detect-new-user-created-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NewIAMUserCreated"
  namespace           = "DetectionEngineering/MITRE"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "HIGH - T1136 - New IAM user created"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.detection_alerts.arn]
  tags = {
    MITRETechnique = "T1136"
    Severity       = "HIGH"
    Project        = var.project_name
  }
}

resource "aws_cloudwatch_event_rule" "detection_alarms" {
  name        = "${var.project_name}-alarm-trigger"
  description = "Routes CloudWatch alarm state changes to detection handler Lambda"
  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      state = {
        value = ["ALARM"]
      }
    }
  })
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "detection_lambda" {
  rule      = aws_cloudwatch_event_rule.detection_alarms.name
  target_id = "DetectionHandlerLambda"
  arn       = aws_lambda_function.detection_handler.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection_alarms.arn
}