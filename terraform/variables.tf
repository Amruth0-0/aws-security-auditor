variable "aws_region" {
    description = "AWS region to deploy resources"
    type        = string
    default     = "us-east-1"
}

variable "vpc_cidr" {
    description = "The CIDR Range (IP addresses for the VPC)"
    type = string
    default = "10.0.0.0/16"
}

variable "availability_zones" {
    description = "Availability Zones Over VPC"
    type = list(string)
    default = ["us-east-1a","us-east-1b"]
}

variable "my_ip" {
    description = "Your public IPv4 address for SSH access"
    type = string
    sensitive = true
}

variable "project_name" {
    description = "predifined project name for the resources"
    type = string
    default = "chainbreak"
}

variable "alert_email" {
    description = "Email address for SNS alert notifications"
    type = string
    sensitive = true
}

variable "rate_expression" {
    description = "EventBridge Schedule Expression eg: rate (1 hour)"
    type = string
    default = "rate(5 minutes)"
}

variable "enable_lambda" {
    description = "Enable or disable the Lambda function"
    type        = bool
    default     = false
}

variable "enable_remediation" {
    description = "Allow the auditor to actually revoke security group rules. False = dry run only."
    type        = bool
    default     = false
}

variable "remediation_whitelist" {
    description = "Ports and CIDRs eligible for automatic revocation"
    type = object({
        ports = list(number)
        cidrs = list(string)
    })
    default = {
        ports = [22, 3389]
        cidrs = ["0.0.0.0/0"]
    }
}

variable "excluded_sg_ids" {
    description = "Security group IDs that are never auto-remediated"
    type        = list(string)
    default     = []
}

variable "severity_threshold" {
    description = "Blast radius score at which a finding is escalated instead of auto-fixed"
    type        = number
    default     = 12
}