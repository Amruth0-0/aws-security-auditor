resource "aws_cloudwatch_event_rule" "auditor_schedule" {
    name = "chainbreak-auditor-schedule"
    description = "Trigger Chainbreak lambda periodically"
    schedule_expression = var.rate_expression
    is_enabled = var.enable_lambda
}

resource "aws_cloudwatch_event_target" "auditor_target" {
    rule = aws_cloudwatch_event_rule.auditor_schedule.name
    target_id = "ChainBreakLambdaTarget"
    arn = aws_lambda_function.auditor.arn
}

resource "aws_lambda_permission" "allow_lambda"{
    statement_id = "allowExecutionFromLambda"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.auditor.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.auditor_schedule.arn
}