resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"

  // CKV_AWS_26: encrypt messages at rest.
  //
  // The alert body is a list of exactly where this account's security holes
  // are, which is worth protecting even though it is sent to one email address.
  //
  // alias/aws/sns is the AWS managed key, so this costs nothing — a customer
  // managed key would be ~$1/month and break the $0 requirement. The trade-off
  // is that the key policy cannot be edited, so publishers must be in the same
  // account; the Lambda is. It also means the publisher now needs explicit KMS
  // permissions, granted in iam.tf.
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Project = var.project_name
  }
}

resource "aws_sns_topic_subscription" "alerts_subscription" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}