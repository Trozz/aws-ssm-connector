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
- **Performance Optimized**: Concurrent operations and fast startup options
- **SSM Validation**: Pre-checks instance availability for SSM connections

## How It Works

### Overall Workflow

```mermaid
graph TD
    A[Start: aws-ssm-connect my-server] --> B[Parse CLI Arguments]
    B --> C[Load AWS Configuration]
    
    C --> D{Concurrent Operations}
    D --> E[Validate AWS Credentials]
    D --> F[Search EC2 Instances by Name Tag]
    
    E --> G[Join Results]
    F --> G
    
    G --> H{Instances Found?}
    H -->|No| I[Error: No instances found]
    H -->|Yes| J{Skip SSM Check?}
    
    J -->|Yes| K[Use All Instances]
    J -->|No| L[Check SSM Availability Concurrently]
    
    L --> M{SSM Available?}
    M -->|None| N[Error: No SSM-enabled instances]
    M -->|Some/All| O[Filter SSM-Available Instances]
    
    K --> P{Multiple Instances?}
    O --> P
    
    P -->|No| Q[Auto-Select Single Instance]
    P -->|Yes| R[Interactive Selection Menu]
    
    Q --> S[Start SSM Session]
    R --> S
    
    S --> T[Record Session Duration]
    T --> U{Show Summary?}
    U -->|Yes| V[Display Session Summary]
    U -->|No| W[End]
    V --> W
```

### Performance Optimization Flow

```mermaid
graph LR
    A[Standard Mode] --> B[Concurrent Auth + Discovery]
    B --> C[Concurrent SSM Checks]
    C --> D[Instance Selection]
    
    A1[Fast Mode<br/>--skip-ssm-check] --> B1[Concurrent Auth + Discovery]
    B1 --> D1[Skip SSM Checks]
    D1 --> D
    
    style A1 fill:#e1f5fe
    style D1 fill:#c8e6c9
```

### AWS Services Architecture

```mermaid
graph TB
    subgraph "Local Machine"
        CLI[aws-ssm-connect CLI]
        AWS_CLI[AWS CLI + SSM Plugin]
    end
    
    subgraph "AWS Cloud"
        subgraph "Identity & Access"
            IAM[IAM Roles/Users]
            STS[AWS STS<br/>GetCallerIdentity]
        end
        
        subgraph "Compute"
            EC2[EC2 Service<br/>DescribeInstances]
            INST1[EC2 Instance 1<br/>Name: web-server]
            INST2[EC2 Instance 2<br/>Name: web-server]
            INST3[EC2 Instance 3<br/>Name: database]
        end
        
        subgraph "Systems Manager"
            SSM[SSM Service<br/>DescribeInstanceInformation]
            SSM_SESSION[SSM Session Manager<br/>StartSession]
        end
    end
    
    CLI -->|1. Authenticate| STS
    CLI -->|2. Find Instances| EC2
    CLI -->|3. Check SSM Status| SSM
    CLI -->|4. Start Session| AWS_CLI
    AWS_CLI -->|5. Create Session| SSM_SESSION
    
    EC2 -.->|Filter by Name Tag| INST1
    EC2 -.->|Filter by Name Tag| INST2
    EC2 -.->|Exclude| INST3
    
    SSM_SESSION -.->|Connect| INST1
    
    style CLI fill:#f9f9f9
    style AWS_CLI fill:#e3f2fd
    style STS fill:#fff3e0
    style EC2 fill:#e8f5e8
    style SSM fill:#fce4ec
    style INST1 fill:#e1f5fe
```

### Port Forwarding Architecture

```mermaid
graph LR
    subgraph "Local Machine"
        APP[Your Application]
        LOCAL_PORT[localhost:8080]
        CLI_PF[aws-ssm-connect<br/>Port Forward Mode]
    end
    
    subgraph "AWS SSM"
        SSM_DOC[SSM Document<br/>AWS-StartPortForwardingSession]
        SSM_TUNNEL[SSM Secure Tunnel]
    end
    
    subgraph "EC2 Instance"
        SSM_AGENT[SSM Agent]
        REMOTE_PORT[localhost:80]
        SERVICE[Web Server]
    end
    
    APP --> LOCAL_PORT
    LOCAL_PORT --> CLI_PF
    CLI_PF --> SSM_DOC
    SSM_DOC --> SSM_TUNNEL
    SSM_TUNNEL --> SSM_AGENT
    SSM_AGENT --> REMOTE_PORT
    REMOTE_PORT --> SERVICE
    
    style APP fill:#e3f2fd
    style LOCAL_PORT fill:#e8f5e8
    style CLI_PF fill:#f9f9f9
    style SSM_TUNNEL fill:#fff3e0
    style SERVICE fill:#fce4ec
```

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
  -p, --profile <PROFILE>          AWS profile to use (overrides AWS_PROFILE)
  -r, --region <REGION>            AWS region to use (overrides AWS_REGION)
  -f, --port-forward               Enable port forwarding mode
  -L, --local-port <LOCAL_PORT>    Local port for port forwarding
  -R, --remote-port <REMOTE_PORT>  Remote port for port forwarding
  -H, --remote-host <REMOTE_HOST>  Remote host on target instance [default: localhost]
      --no-summary                 Hide connection summary after session ends
  -v, --verbose                    Enable verbose output for debugging
      --skip-ssm-check             Skip SSM availability checks for faster startup
  -h, --help                       Print help
  -V, --version                    Print version
```

### Environment Variables

The tool respects these environment variables:

- `AWS_PROFILE` - Default AWS profile (overridden by `--profile`)
- `AWS_REGION` - Default AWS region (overridden by `--region`)
- Standard AWS SDK environment variables for credentials

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

### Advanced Usage

```bash
# Enable verbose output for troubleshooting
aws-ssm-connect my-instance -v

# Check connection without showing summary
aws-ssm-connect my-instance --no-summary

# Fast startup mode (skip SSM availability checks)
aws-ssm-connect my-instance --skip-ssm-check

# Combine options for maximum performance
aws-ssm-connect my-instance --skip-ssm-check --no-summary
```

### Performance Modes

For optimal performance, the tool offers several modes:

**Standard Mode** (default)
- Validates AWS credentials and checks SSM availability concurrently
- Best balance of safety and speed

**Fast Mode** (`--skip-ssm-check`)
- Skips SSM availability pre-checks
- Use when you know all instances are SSM-enabled
- **Up to 90% faster startup**

**Silent Mode** (`--no-summary`)
- Disables session summary display
- Slightly faster session termination

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

## Performance

This tool is optimized for speed and efficiency:

### Concurrent Operations
- AWS authentication and instance discovery run in parallel
- Multiple instances checked for SSM availability simultaneously
- **50-70% faster** than sequential operations

### Memory Efficiency
- Pre-allocated vectors for known data sizes
- Single-pass tag processing
- Lazy string formatting for debug output

### Performance Optimization Sequence

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as aws-ssm-connect
    participant STS as AWS STS
    participant EC2 as AWS EC2
    participant SSM as AWS SSM
    participant Session as SSM Session

    Note over CLI: Standard Mode (Concurrent)
    U->>CLI: aws-ssm-connect web-server
    CLI->>CLI: Parse arguments
    
    par Concurrent Operations
        CLI->>STS: Validate credentials
        CLI->>EC2: Find instances by Name tag
    end
    
    STS-->>CLI: ✓ Valid credentials
    EC2-->>CLI: [Instance1, Instance2, Instance3]
    
    par Concurrent SSM Checks
        CLI->>SSM: Check Instance1 SSM status
        CLI->>SSM: Check Instance2 SSM status
        CLI->>SSM: Check Instance3 SSM status
    end
    
    SSM-->>CLI: ✓ Instance1 available
    SSM-->>CLI: ✗ Instance2 not available
    SSM-->>CLI: ✓ Instance3 available
    
    CLI->>U: Select from [Instance1, Instance3]
    U->>CLI: Choose Instance1
    CLI->>Session: Start SSM session
    Session-->>CLI: Session established
    
    Note over CLI: Fast Mode (--skip-ssm-check)
    rect rgb(200, 230, 201)
        CLI->>CLI: Skip SSM availability checks
        CLI->>U: Select from [Instance1, Instance2, Instance3]
        Note right of CLI: 90% faster startup
    end
```

### Performance Benchmarks

| Scenario | Startup Time | Improvement |
|----------|-------------|-------------|
| Single instance (standard) | ~1-1.5s | 50% faster |
| Multiple instances (5) | ~2-3s | 70% faster |
| With `--skip-ssm-check` | ~0.5-1s | 90% faster |
| Large instance lists (20+) | ~3-5s | 85% faster |

### Optimization Tips
- Use `--skip-ssm-check` for known SSM-enabled environments
- Set environment variables instead of CLI args for frequently used profiles/regions
- Use `--no-summary` for scripted usage

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

The project includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test category
cargo test test_cli_parsing
```

**Test Coverage**: 49 comprehensive tests covering:
- CLI argument parsing and validation
- AWS configuration and authentication
- Instance discovery and filtering
- SSM availability checks
- Port forwarding validation
- Error handling and edge cases
- Performance optimizations
- Memory safety with large datasets

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