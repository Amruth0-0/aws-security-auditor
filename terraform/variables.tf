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