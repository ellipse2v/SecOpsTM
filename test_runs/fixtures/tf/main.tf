resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
resource "aws_db_instance" "db" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  publicly_accessible = true
}
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
resource "aws_lb" "front" {
  name = "front"
}
