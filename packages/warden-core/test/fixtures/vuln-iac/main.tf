resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Action = "*", Resource = "*" }] })
}
