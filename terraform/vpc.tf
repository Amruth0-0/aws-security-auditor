resource "aws_vpc" "main" {
    cidr_block = var.vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support = true

    tags = {
        Name = "auditor-vpc"
        Project = "chainbreak"
    }
}

resource "aws_subnet" "public" {
     count = length(var.availability_zones)
     vpc_id = aws_vpc.main.id
     cidr_block = cidrsubnet(var.vpc_cidr, 8, count.index)
     
     map_public_ip_on_launch = true
     availability_zone = var.availability_zones[count.index]

     tags = {
         Name = "auditor-public-subnet-${count.index + 1}"
         Project = "chainbreak"
     }
}

resource "aws_subnet" "private" {
    count = length(var.availability_zones)
    vpc_id = aws_vpc.main.id
    cidr_block = cidrsubnet(var.vpc_cidr, 8, count.index + length(var.availability_zones))

    map_public_ip_on_launch = false
    availability_zone = var.availability_zones[count.index]

    tags = {
         Name = "auditor-private-subnet-${count.index + 1}"
         Project = "chainbreak"
    }
}
