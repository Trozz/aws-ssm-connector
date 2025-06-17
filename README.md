# AWS SSM Connect

A command-line tool for connecting to AWS EC2 instances via AWS Systems Manager (SSM) using instance Name tags. This tool simplifies the process of establishing SSM sessions by allowing you to connect using human-readable instance names instead of instance IDs.

## Features

- **Name-based Connection**: Connect to EC2 instances using their Name tag instead of instance IDs
- **Interactive Selection**: When multiple instances share the same name, select from a list
- **Port Forwarding**: Support for local port forwarding to access services on remote instances
- **Session Management**: Clear session summaries with connection details and duration
- **Multi-Profile Support**: Works with multiple AWS profiles and regions
- **Colored Output**: Enhanced terminal output with color-coded messages
- **Verbose Debugging**: Optional verbose mode for troubleshooting

## Prerequisites

- [AWS CLI](https://aws.amazon.com/cli/) installed and configured
- AWS Session Manager Plugin installed ([Installation Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html))
- Rust toolchain (for building from source)
- Appropriate AWS IAM permissions for EC2 and SSM
- EC2 instances with SSM Agent installed and running

## Installation

### From Source

```bash
git clone https://github.com/trozz/ssm-connector.git
cd ssm-connector
cargo build --release
```

The binary will be available at `target/release/aws-ssm-connect`

### Install to PATH

```bash
cargo install --path .
```

## Usage

### Basic Connection

Connect to an instance by its Name tag:

```bash
aws-ssm-connect my-instance-name
```

### With AWS Profile and Region

```bash
aws-ssm-connect my-instance-name --profile production --region us-west-2
```

### Port Forwarding

Forward local port 8080 to remote port 80:

```bash
aws-ssm-connect my-instance-name -f -L 8080 -R 80
```

Forward to a specific host on the target instance:

```bash
aws-ssm-connect my-instance-name -f -L 3306 -R 3306 -H database.internal
```

### Command-Line Options

```
Usage: aws-ssm-connect [OPTIONS] <INSTANCE_NAME>

Arguments:
  <INSTANCE_NAME>  Instance name (Name tag value)

Options:
  -p, --profile <PROFILE>          AWS profile to use
  -r, --region <REGION>            AWS region to use
  -f, --port-forward               Enable port forwarding mode
  -L, --local-port <LOCAL_PORT>    Local port for port forwarding
  -R, --remote-port <REMOTE_PORT>  Remote port for port forwarding
  -H, --remote-host <REMOTE_HOST>  Remote host on target instance [default: localhost]
      --no-summary                 Hide connection summary after session ends
  -v, --verbose                    Enable verbose output for debugging
  -h, --help                       Print help
  -V, --version                    Print version
```

## Examples

### Interactive Shell Session

```bash
# Connect to an instance named "web-server"
aws-ssm-connect web-server

# Connect using a specific AWS profile
aws-ssm-connect web-server --profile staging

# Connect to an instance in a specific region
aws-ssm-connect web-server --region eu-west-1
```

### Port Forwarding

```bash
# Forward local port 8080 to remote port 80 (web server)
aws-ssm-connect web-server -f -L 8080 -R 80

# Forward local port 3306 to MySQL on the instance
aws-ssm-connect database-server -f -L 3306 -R 3306

# Forward to a different host accessible from the instance
aws-ssm-connect bastion -f -L 5432 -R 5432 -H internal-db.local
```

### Debugging

```bash
# Enable verbose output for troubleshooting
aws-ssm-connect my-instance -v

# Check connection without showing summary
aws-ssm-connect my-instance --no-summary
```

## AWS Configuration

This tool uses the standard AWS SDK credential chain:

1. Command-line options (`--profile`, `--region`)
2. Environment variables (`AWS_PROFILE`, `AWS_REGION`)
3. AWS credentials file (`~/.aws/credentials`)
4. AWS config file (`~/.aws/config`)
5. Instance metadata (if running on EC2)

## Required IAM Permissions

The IAM user or role needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ssm:DescribeInstanceInformation",
                "ssm:StartSession",
                "ssm:TerminateSession"
            ],
            "Resource": "*"
        }
    ]
}
```

For port forwarding, ensure the SSM documents are accessible:
- `AWS-StartPortForwardingSession`
- `AWS-StartPortForwardingSessionToRemoteHost`

## Instance Requirements

Target EC2 instances must:

1. Have SSM Agent installed and running
2. Have an IAM role with `AmazonSSMManagedInstanceCore` policy attached
3. Be in a running state
4. Have network connectivity to SSM endpoints (or use VPC endpoints)

## Session Summary

After each session, the tool displays a summary including:

- Instance details (ID, name, type, IP addresses)
- Connection type (Interactive Shell or Port Forwarding)
- Port forwarding details (if applicable)
- Session duration
- AWS profile and region used

To disable the summary, use the `--no-summary` flag.

## Troubleshooting

### Instance Not Available for SSM

If you see "Instance is not available for SSM connection", check:

1. SSM Agent is installed and running on the instance
2. Instance has the required IAM role attached
3. Security groups allow outbound HTTPS (443) traffic
4. Instance can reach SSM endpoints

### Multiple Instances Found

When multiple instances have the same Name tag, the tool presents an interactive selection menu. Use arrow keys to select the desired instance.

### Connection Timeouts

For instances in private subnets without internet access, ensure:
- VPC endpoints for SSM are configured
- Security groups allow traffic to VPC endpoints
- Route tables are properly configured

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Release Build

```bash
cargo build --release
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Created and maintained by [trozz](https://github.com/trozz)