//Trust Policy
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}


//Permission Policy
data "aws_iam_policy_document" "lambda_readonly" {
  statement {
    effect = "Allow"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:ListAllMyBuckets", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["rds:DescribeDBInstances"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions   = ["sns:Publish"]
    resources = ["*"] //Todo
  }

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"] //Todo
  }
}

//IAM Policy
resource "aws_iam_policy" "lambda_readonly" {
  name        = "auditor_readOnly"
  description = "Read-only permission for Lambda Scanner"

  policy = data.aws_iam_policy_document.lambda_readonly.json
}

//IAM Role
resource "aws_iam_role" "lambda_execution" {
  name                = "auditor_lambda_role"
  assume_role_policy  = data.aws_iam_policy_document.lambda_assume_role.json
}

//Attach Policies
resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = aws_iam_policy.lambda_readonly.arn
}