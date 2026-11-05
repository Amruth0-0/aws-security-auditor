resource "aws_lambda_function" "auditor" {
  function_name    = "${var.project_name}-auditor"
  runtime          = "nodejs20.x"
  handler          = "src/handler.handler"
  role             = aws_iam_role.lambda_execution.arn
  filename         = "../dist/lambda.zip"
  source_code_hash = filebase64sha256("../dist/lambda.zip")
  memory_size      = 128
  timeout          = 60

  environment {
    variables = {
      FINDINGS_TABLE_NAME   = aws_dynamodb_table.findings.name
      SNS_TOPIC_ARN         = aws_sns_topic.alerts.arn
      REMEDIATION_ENABLED   = tostring(var.enable_remediation)
      REMEDIATION_WHITELIST = jsonencode(var.remediation_whitelist)
      EXCLUDED_SG_IDS       = join(",", var.excluded_sg_ids)
      SEVERITY_THRESHOLD    = tostring(var.severity_threshold)
    }
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_lambda_function_event_invoke_config" "auditor" {
  function_name          = aws_lambda_function.auditor.function_name
  maximum_retry_attempts = 0
}