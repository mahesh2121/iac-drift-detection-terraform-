# Test EC2 Instance - IaC Test
# This will test if the system correctly identifies Terraform changes as IaC

resource "aws_instance" "test_ec2" {
  ami           = "ami-0ea87431b78a82070" # Replace with a valid AMI ID for your region
  instance_type = "t2.micro"

  tags = {
    Name        = "iac-test-instance"
    CreatedBy   = "terraform"
    Environment = "test"
  }
}

# Output the instance details
output "instance_id" {
  value = aws_instance.test_ec2.id
}

output "instance_public_ip" {
  value = aws_instance.test_ec2.public_ip
}