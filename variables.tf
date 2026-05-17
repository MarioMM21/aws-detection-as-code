variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "detection-as-code"
}

variable "alert_email" {
  description = "Email address for detection alerts"
  type        = string
  default     = "mylesmariom@gmail.com"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "security-lab"
}