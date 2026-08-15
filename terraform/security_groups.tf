resource "aws_security_group" "safe" {
  description = "Safe security group for demo"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    cidr_blocks = [var.vpc_cidr]
    from_port = 443
    to_port = 443
  }

  egress {
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 0
  }

  tags = {
    Name = "auditor-safe-sg"
    Project = "chainbreak"
  }
}

resource "aws_security_group" "demo_target" {
    description = "Security group that will be intentionally misconfigured"
    vpc_id = aws_vpc.main.id

    egress {
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        from_port = 0
        to_port = 0
    }

    tags = {
      Name = "auditor-demo-sg"
      Project = "chainbreak"
    }

    lifecycle {
        ignore_changes = [ingress] 
    }   
}

resource "aws_security_group" "ec2_demo" {
    description = "Security group for demo EC2 instance"
    vpc_id = aws_vpc.main.id

    ingress {
        protocol = "tcp"
        cidr_blocks = [var.my_ip]
        from_port = 22
        to_port = 22
    }

    egress {
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        from_port = 0
        to_port = 0
    }

    tags = {
        Name = "ec2-demo-sg"
        Project = "chainbreak"
    }
}

