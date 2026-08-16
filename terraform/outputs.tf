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