terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Create VPC
resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"
}

# Create Subnet
resource "aws_subnet" "my_vpc_subnet" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = "10.1.1.0/24"
  availability_zone = "ap-south-1a"
  map_public_ip_on_launch = true
}

# Create Routing Table
resource "aws_route_table" "my_vpc_subnet_rt" {
  vpc_id = aws_vpc.my_vpc.id  
}

# Routing Table Association to Subnet
resource "aws_route_table_association" "my_vpc_rt_association" {
  subnet_id      = aws_subnet.my_vpc_subnet.id
  route_table_id = aws_route_table.my_vpc_subnet_rt.id  
}

# Create Internet Gateway
resource "aws_internet_gateway" "my_vpc_igw" {
  vpc_id = aws_vpc.my_vpc.id
}

# Internet Gateway Association to Routing Table
resource "aws_route" "internet_route" {
  route_table_id         = aws_route_table.my_vpc_subnet_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.my_vpc_igw.id
}

# Create Security Group
resource "aws_security_group" "my_sg" {
    name        = "my_sg"
    vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow SSH traffic from any IP
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTP traffic from any IP
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTP traffic from any IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Allow all outbound traffic
  }
}

# Create IAM Role
resource "aws_iam_role" "my_role_for_cw_agent" {
    name               = "cw_agent_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach Policy to IAM Role
resource "aws_iam_role_policy_attachment" "my_role_policy_attachment" {
  role       = aws_iam_role.my_role_for_cw_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_role_policy_attachment" "my_role_policy_attachment_cw" {
  role       = aws_iam_role.my_role_for_cw_agent.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Create IAM Instance Profile
resource "aws_iam_instance_profile" "my_instance_profile" {
  name = "my_instance_profile"
  role = aws_iam_role.my_role_for_cw_agent.name
}

# Create Key Pair
resource "tls_private_key" "rsa_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "aws_key_pair" "my_keypair" {
  key_name   = "my_key"
  public_key = tls_private_key.rsa_key.public_key_openssh
}
resource "local_file" "my_key" {
  content  = tls_private_key.rsa_key.private_key_pem
  filename = "${aws_key_pair.my_keypair.key_name}.pem"
}

# Create SSM parameter
data "aws_ssm_parameter" "config_json" {
  name = "${aws_ssm_parameter.CWAgent_Config.name}"
}

# SSM parameter for cloudwatch configuration
resource "aws_ssm_parameter" "CWAgent_Config" {
  name        = "CWAgent_Config"
  description = "CWAgent Config"
  type        = "String"
  value       = file("./config.json")
}

# Create Launch Template
resource "aws_launch_template" "my_inst_launch_temp" {
  name          =  "my_template"
  image_id      = "ami-0449c34f967dbf18a"
  instance_type = "t2.micro"
  key_name      = aws_key_pair.my_keypair.key_name

  user_data = base64encode(local.user_data)

  network_interfaces {
    security_groups = [aws_security_group.my_sg.id]
    associate_public_ip_address = true
    subnet_id = aws_subnet.my_vpc_subnet.id
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.my_instance_profile.name
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      name =  "test"
    }
  }
}

locals {
  user_data = <<-EOF
    #!/bin/bash
    sudo yum update -y
    sudo yum install httpd -y
    sudo systemctl start httpd
    sudo systemctl enable httpd
    sudo systemctl status httpd
    sudo yum install amazon-cloudwatch-agent -y
    sudo systemctl start amazon-cloudwatch-agent
    sudo systemctl enable amazon-cloudwatch-agent
    wget https://github.com/samitkumarpatel/hello-world/releases/download/v1.0.20/hello-world-1.0.0-SNAPSHOT.jar
    wget https://download.java.net/openjdk/jdk21/ri/openjdk-21+35_linux-x64_bin.tar.gz
    tar -xzvf openjdk-21+35_linux-x64_bin.tar.gz
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c ssm:CWAgent_Config
    ./jdk-21/bin/java -jar ./hello-world-1.0.0-SNAPSHOT.jar
  EOF
}

# Create Auto Scaling Group
resource "aws_autoscaling_group" "my_asg" {
    name                = "my_asg"
    //desired_capacity    = 1
    min_size            = 1
    max_size            = 5
    //health_check_type   = "EC2" # default is EC2 you can use load balancer also
    vpc_zone_identifier = [aws_subnet.my_vpc_subnet.id]
    launch_template {
      id = aws_launch_template.my_inst_launch_temp.id
      version = "$Latest"
    }
}

# Create Auto Scaling Policy (Scale Up)
resource "aws_autoscaling_policy" "cpu_scaling_up" {
    name                   = "cpu_scaling_up_policy"
    scaling_adjustment     = 1
    adjustment_type        = "ChangeInCapacity"
    cooldown               = 300
    autoscaling_group_name = aws_autoscaling_group.my_asg.name
}

# Cloudwatch matric alaram
resource "aws_cloudwatch_metric_alarm" "my_cwa_scale_up" {
  alarm_name          = "my_cwa_up_alarm"
  alarm_description   = "Greater than or equalto threshold"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "50"
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.my_asg.name
  }
  actions_enabled = true
  alarm_actions = [aws_autoscaling_policy.cpu_scaling_up.arn]
}

# Create Auto Scaling Policy (Scale Down)
resource "aws_autoscaling_policy" "cpu_scaling_down" {
    name                   = "cpu_scaling_down_policy"
    scaling_adjustment     = -1
    adjustment_type        = "ChangeInCapacity"
    cooldown               = 300
    autoscaling_group_name = aws_autoscaling_group.my_asg.name
}

# Cloudwatch matric alaram
resource "aws_cloudwatch_metric_alarm" "my_cwa_scale_down" {
  alarm_name          = "my_cwa_down_alarm"
  alarm_description   = "Less than or equalto threshold"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "25"
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.my_asg.name
  }
  actions_enabled = true
  alarm_actions = [aws_autoscaling_policy.cpu_scaling_down.arn]
}

# Create Load Balancer Target Group
resource "aws_lb_target_group" "my_lb_tgt" {
    vpc_id   = aws_vpc.my_vpc.id    
    name     = "my-lb-tgt-group"
    port     = 80
    protocol = "HTTP"
    
}
