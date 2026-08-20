resource "aws_dynamodb_table" "findings" {
    name           = "${var.project_name}-findings"
    billing_mode   = "PAY_PER_REQUEST"
    hash_key       = "findingId"

    global_secondary_index {
        name  = "status-index"
        hash_key = "status"
        projection_type = "ALL"

    }

    attribute {
        name = "findingId"
        type = "S"
    }

    attribute {
        name = "status"
        type = "S"
    }

    tags = {
        Project = var.project_name
    }
}