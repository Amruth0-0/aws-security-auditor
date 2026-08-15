resource "aws_network_acl" "public_nacl" {
    vpc_id = aws_vpc.main.id

    ingress {
        protocol = "tcp"
        rule_no = 100
        action = "allow"
        cidr_block = "0.0.0.0/0"
        from_port = 22
        to_port = 22
    }
    
    ingress {
        protocol = "tcp"
        rule_no = 200
        action = "allow"
        cidr_block = "0.0.0.0/0"
        from_port = 80
        to_port = 80
    }
    
    ingress {
        protocol = "tcp"
        rule_no = 300
        action = "allow"
        cidr_block = "0.0.0.0/0"
        from_port = 443
        to_port = 443
    }

    ingress {
        protocol = "tcp"
        rule_no = 400
        action = "allow"
        cidr_block = "0.0.0.0/0"
        from_port = 1024
        to_port = 65535
    }

    egress {
        protocol = "-1"
        rule_no = 100
        action = "allow"
        cidr_block = "0.0.0.0/0"
        from_port = 0
        to_port = 0

    }
    tags = {
        Name = "auditor-public-nacl"
        Project = "chainbreak"
    }
}

resource "aws_network_acl" "private_nacl" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "-1"
    rule_no = 100
    action = "allow"
    cidr_block = var.vpc_cidr
    from_port = 0
    to_port = 0
  }

  egress {
    protocol = "-1"
    rule_no = 100
    action = "allow"
    cidr_block = var.vpc_cidr
    from_port = 0
    to_port = 0
  }

  tags = {
    Name = "auditor-private-nacl"
    Project = "chainbreak"
  }
}

resource "aws_network_acl_association" "public" {
    count = length(var.availability_zones)

    subnet_id = aws_subnet.public[count.index].id
    network_acl_id = aws_network_acl.public_nacl.id
}

resource "aws_network_acl_association" "private" {
    count = length(var.availability_zones)

    subnet_id = aws_subnet.private[count.index].id
    network_acl_id = aws_network_acl.private_nacl.id
}