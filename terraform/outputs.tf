output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution.arn
}

output "vpc_id" {
  description = "Id of the vpc created"
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "Id's of the public subnets"
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Id's of the private subnets"
  value = aws_subnet.private[*].id
}

output "dynamo_table_name" {
  description = "Name of the dynamoDB Table"
  value = aws_dynamodb_table.findings.name
}

output "dynamo_table_arn" {
  description = "ARN of the dynamoDB Table"
  value = aws_dynamodb_table.findings.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS alert topic"
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_arn" {
  description= "ARN of the Lambda function"
  value = aws_lambda_function.auditor.arn
}