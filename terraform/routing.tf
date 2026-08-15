resource "aws_internet_gateway" "main_igw" {
   vpc_id = aws_vpc.main.id
   
   tags = {
     Name =  "auditor-igw"
     Project = "chainbreak"
   }
}

resource "aws_route_table" "private_route" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "auditor-private-route"
    Project = "chainbreak"
  }

}

resource "aws_route_table" "public_route" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }

  tags = {
    Name = "auditor-route"
    Project = "chainbreak"
  }
}

resource "aws_route_table_association" "public" {
   count = length(var.availability_zones)
   subnet_id = aws_subnet.public[count.index].id
   route_table_id = aws_route_table.public_route.id
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)
  subnet_id = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private_route.id
}