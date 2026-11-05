// CKV2_AWS_12: a VPC's default security group allows all traffic between
// anything assigned to it. Declaring it here with no ingress or egress blocks
// strips every rule, so a resource launched without an explicit security group
// gets no connectivity instead of silently inheriting an allow-all one.
// Terraform adopts the existing group rather than creating a new one.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name    = "auditor-default-sg-locked"
    Project = "chainbreak"
  }
}

resource "aws_security_group" "safe" {
  description = "Safe security group for demo"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from within the VPC only"
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    from_port   = 443
    to_port     = 443
  }

  egress {
    description = "Allow all outbound"
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
  }

  tags = {
    Name    = "auditor-safe-sg"
    Project = "chainbreak"
  }
}

resource "aws_security_group" "demo_target" {
  description = "Security group that will be intentionally misconfigured"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Allow all outbound"
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
  }

  tags = {
    Name    = "auditor-demo-sg"
    Project = "chainbreak"
  }

  // Starts with no ingress. The bad rule is added by hand in the console during
  // the demo; ignoring ingress changes stops Terraform fighting that or
  // reporting it as drift.
  lifecycle {
    ignore_changes = [ingress]
  }
}

resource "aws_security_group" "ec2_demo" {
  description = "Security group for demo EC2 instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from the operator's IP only"
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    from_port   = 22
    to_port     = 22
  }

  egress {
    description = "Allow all outbound"
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
  }

  tags = {
    Name    = "ec2-demo-sg"
    Project = "chainbreak"
  }
}
