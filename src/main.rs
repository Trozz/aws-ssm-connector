// Cargo.toml
/*
[package]
name = "aws-ssm-connect"
version = "0.1.0"
edition = "2021"

[dependencies]
aws-config = "1.1.0"
aws-sdk-ec2 = "1.8.0"
aws-sdk-ssm = "1.8.0"
aws-sdk-sts = "1.8.0"
clap = { version = "4.4", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
colored = "2.0"
anyhow = "1.0"
dialoguer = "0.11"
*/

use anyhow::{anyhow, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_config::Region;
use aws_sdk_ec2::types::Filter;
use clap::Parser;
use colored::*;
use dialoguer::Select;
use std::process::Command;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "aws-ssm-connect")]
#[command(about = "Connect to AWS EC2 instances via SSM using instance Name tag")]
#[command(version = "1.0.0")]
struct Cli {
    /// Instance name (Name tag value)
    instance_name: String,

    /// AWS profile to use (defaults to AWS_PROFILE env var or default profile)
    #[arg(short = 'p', long = "profile")]
    profile: Option<String>,

    /// AWS region to use (defaults to AWS_REGION env var or config file)
    #[arg(short = 'r', long = "region")]
    region: Option<String>,

    /// Enable port forwarding mode
    #[arg(short = 'f', long = "port-forward")]
    port_forward: bool,

    /// Local port for port forwarding
    #[arg(short = 'L', long = "local-port")]
    local_port: Option<u16>,

    /// Remote port for port forwarding
    #[arg(short = 'R', long = "remote-port")]
    remote_port: Option<u16>,

    /// Remote host on target instance
    #[arg(short = 'H', long = "remote-host", default_value = "localhost")]
    remote_host: String,

    /// Hide connection summary after session ends
    #[arg(long = "no-summary")]
    no_summary: bool,

    /// Enable verbose output for debugging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct InstanceInfo {
    instance_id: String,
    name: String,
    instance_type: String,
    state: String,
    private_ip: Option<String>,
    public_ip: Option<String>,
    tags: Vec<(String, String)>,
}

#[derive(Debug)]
struct SessionSummary {
    instance_info: InstanceInfo,
    session_type: String,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    remote_host: Option<String>,
    duration: std::time::Duration,
    profile: Option<String>,
    region: Option<String>,
}

fn print_info(message: &str) {
    eprintln!("{} {}", "[INFO]".blue().bold(), message);
}

fn print_debug(message: &str, verbose: bool) {
    if verbose {
        eprintln!("{} {}", "[DEBUG]".cyan().bold(), message);
    }
}

fn print_success(message: &str) {
    eprintln!("{} {}", "[SUCCESS]".green().bold(), message);
}

fn print_warning(message: &str) {
    eprintln!("{} {}", "[WARNING]".yellow().bold(), message);
}

fn print_error(message: &str) {
    eprintln!("{} {}", "[ERROR]".red().bold(), message);
}

async fn get_aws_config(
    profile: Option<String>,
    region: Option<String>,
) -> Result<aws_config::SdkConfig> {
    // AWS configuration chain (in order of precedence):
    // 1. CLI arguments (--profile, --region)
    // 2. Environment variables (AWS_PROFILE, AWS_REGION)
    // 3. AWS credentials file (~/.aws/credentials)
    // 4. AWS config file (~/.aws/config)
    // 5. Instance metadata (if running on EC2)

    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    // Set region if provided, otherwise use default chain
    if let Some(region_str) = region {
        let region = Region::new(region_str);
        let region_provider = RegionProviderChain::default_provider().or_else(region);
        config_loader = config_loader.region(region_provider);
    }

    // Set profile if provided, otherwise use default
    if let Some(profile) = profile {
        config_loader = config_loader.profile_name(profile);
    }

    let config = config_loader.load().await;
    Ok(config)
}

async fn validate_aws_config(config: &aws_config::SdkConfig, verbose: bool) -> Result<()> {
    print_debug("Validating AWS configuration...", verbose);

    let sts_client = aws_sdk_sts::Client::new(config);

    match sts_client.get_caller_identity().send().await {
        Ok(_) => {
            print_debug("AWS authentication successful", verbose);
            Ok(())
        }
        Err(e) => Err(anyhow!("Failed to authenticate with AWS: {}", e)),
    }
}

async fn find_instances_by_name(
    ec2_client: &aws_sdk_ec2::Client,
    instance_name: &str,
    verbose: bool,
) -> Result<Vec<InstanceInfo>> {
    print_debug(
        &format!("Searching for instances with Name tag: '{}'", instance_name),
        verbose,
    );

    let name_filter = Filter::builder()
        .name("tag:Name")
        .values(instance_name)
        .build();

    let state_filter = Filter::builder()
        .name("instance-state-name")
        .values("running")
        .build();

    let response = ec2_client
        .describe_instances()
        .filters(name_filter)
        .filters(state_filter)
        .send()
        .await?;

    let mut instances = Vec::new();

    for reservation in response.reservations() {
        for instance in reservation.instances() {
            let name = instance
                .tags()
                .iter()
                .find(|tag| tag.key() == Some("Name"))
                .and_then(|tag| tag.value())
                .unwrap_or("Unknown")
                .to_string();

            let tags: Vec<(String, String)> = instance
                .tags()
                .iter()
                .filter_map(|tag| {
                    if let (Some(key), Some(value)) = (tag.key(), tag.value()) {
                        Some((key.to_string(), value.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            let instance_info = InstanceInfo {
                instance_id: instance.instance_id().unwrap_or("Unknown").to_string(),
                name,
                instance_type: instance
                    .instance_type()
                    .map(|t| t.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                state: instance
                    .state()
                    .and_then(|s| s.name())
                    .map(|n| n.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                private_ip: instance.private_ip_address().map(|ip| ip.to_string()),
                public_ip: instance.public_ip_address().map(|ip| ip.to_string()),
                tags,
            };

            instances.push(instance_info);
        }
    }

    Ok(instances)
}

async fn check_ssm_availability(
    ssm_client: &aws_sdk_ssm::Client,
    instance_id: &str,
    verbose: bool,
) -> Result<()> {
    print_debug(
        &format!("Checking SSM availability for instance: {}", instance_id),
        verbose,
    );

    let response = ssm_client
        .describe_instance_information()
        .filters(
            aws_sdk_ssm::types::InstanceInformationStringFilter::builder()
                .key("InstanceIds")
                .values(instance_id)
                .build()?,
        )
        .send()
        .await?;

    if response.instance_information_list().is_empty() {
        return Err(anyhow!(
            "Instance {} is not available for SSM connection.\n\
            This could be because:\n\
            - SSM agent is not installed or not running\n\
            - Instance doesn't have the required IAM role\n\
            - Instance is not reachable by SSM service",
            instance_id
        ));
    }

    print_debug("Instance is available for SSM connection", verbose);
    Ok(())
}

fn display_instance_info(instance: &InstanceInfo, index: usize) {
    eprintln!(
        "{} Instance: {}",
        format!("[{}]", index).yellow().bold(),
        instance.instance_id.green().bold()
    );
    eprintln!("    Name: {}", instance.name);
    eprintln!("    Type: {}", instance.instance_type);
    eprintln!("    State: {}", instance.state);
    eprintln!(
        "    Private IP: {}",
        instance.private_ip.as_deref().unwrap_or("N/A")
    );
    eprintln!(
        "    Public IP: {}",
        instance.public_ip.as_deref().unwrap_or("N/A")
    );

    let other_tags: Vec<_> = instance
        .tags
        .iter()
        .filter(|(key, _)| key != "Name")
        .collect();

    if !other_tags.is_empty() {
        eprintln!("    Other Tags:");
        for (key, value) in other_tags {
            eprintln!("    {}: {}", key, value);
        }
    }
    eprintln!();
}

fn select_instance(instances: &[InstanceInfo]) -> Result<&InstanceInfo> {
    print_warning(&format!(
        "Found {} instances with the specified name:",
        instances.len()
    ));
    eprintln!();

    for (i, instance) in instances.iter().enumerate() {
        display_instance_info(instance, i + 1);
    }

    let selection_items: Vec<String> = instances
        .iter()
        .map(|instance| format!("{} ({})", instance.name, instance.instance_id))
        .collect();

    let selection = Select::new()
        .with_prompt("Please select an instance")
        .items(&selection_items)
        .interact()?;

    Ok(&instances[selection])
}

async fn start_ssm_session(
    instance_id: &str,
    profile: Option<String>,
    region: Option<String>,
    port_forward: bool,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    remote_host: &str,
) -> Result<()> {
    let mut cmd = Command::new("aws");
    cmd.args(["ssm", "start-session"]);

    if let Some(profile) = profile.as_ref() {
        cmd.args(["--profile", profile]);
    }

    if let Some(region) = region.as_ref() {
        cmd.args(["--region", region]);
    }

    cmd.args(["--target", instance_id]);

    if port_forward {
        let local_port =
            local_port.ok_or_else(|| anyhow!("Local port required for port forwarding"))?;
        let remote_port =
            remote_port.ok_or_else(|| anyhow!("Remote port required for port forwarding"))?;

        if remote_host == "localhost" || remote_host == "127.0.0.1" {
            cmd.args(["--document-name", "AWS-StartPortForwardingSession"])
                .args([
                    "--parameters",
                    &format!("localPortNumber={},portNumber={}", local_port, remote_port),
                ]);
        } else {
            cmd.args([
                "--document-name",
                "AWS-StartPortForwardingSessionToRemoteHost",
            ])
            .args([
                "--parameters",
                &format!(
                    "localPortNumber={},portNumber={},host={}",
                    local_port, remote_port, remote_host
                ),
            ]);
        }

        print_info(&format!(
            "Port forwarding: localhost:{} → {}:{}",
            local_port, remote_host, remote_port
        ));
        print_info(&format!(
            "Access at: {}",
            format!("http://localhost:{}", local_port).green()
        ));
    } else {
        print_info("Starting SSM session...");
    }

    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow!(
            "SSM session failed with exit code: {:?}",
            status.code()
        ));
    }

    Ok(())
}

fn print_session_summary(summary: &SessionSummary) {
    eprintln!();

    if summary.session_type == "Port Forwarding" {
        print_success("Port forwarding session completed");
    } else {
        print_success("SSM session completed");
    }

    let border = "━".repeat(75).blue();
    eprintln!("{}", border);
    eprintln!("{}", "SESSION SUMMARY".green().bold());
    eprintln!("{}", border);

    eprintln!("{}", "Instance Details:".yellow().bold());
    eprintln!(
        "  • Instance ID: {}",
        summary.instance_info.instance_id.green()
    );
    eprintln!("  • Name: {}", summary.instance_info.name);
    eprintln!("  • Type: {}", summary.instance_info.instance_type);
    eprintln!(
        "  • Private IP: {}",
        summary.instance_info.private_ip.as_deref().unwrap_or("N/A")
    );
    eprintln!("  • State: {}", summary.instance_info.state);
    eprintln!();

    eprintln!("{}", "Connection Details:".yellow().bold());
    eprintln!("  • Session Type: {}", summary.session_type.green());

    if let (Some(local_port), Some(remote_port)) = (summary.local_port, summary.remote_port) {
        eprintln!("  • Local Port: {}", local_port.to_string().green());
        eprintln!("  • Remote Port: {}", remote_port.to_string().green());
        if let Some(ref remote_host) = summary.remote_host {
            eprintln!("  • Remote Host: {}", remote_host);
        }
    }

    eprintln!(
        "  • Duration: {}",
        format_duration(summary.duration).green()
    );
    eprintln!(
        "  • Profile: {}",
        summary.profile.as_deref().unwrap_or("default")
    );
    eprintln!(
        "  • Region: {}",
        summary.region.as_deref().unwrap_or("default")
    );
    eprintln!("{}", border);
}

fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Validate port forwarding arguments
    if cli.port_forward && (cli.local_port.is_none() || cli.remote_port.is_none()) {
        print_error("Port forwarding mode requires both --local-port and --remote-port.");
        std::process::exit(1);
    }

    print_debug("AWS SSM Connect Tool", cli.verbose);
    print_debug(
        &format!("Profile: {}", cli.profile.as_deref().unwrap_or("default")),
        cli.verbose,
    );
    print_debug(
        &format!(
            "Region: {}",
            cli.region.as_deref().unwrap_or("default (from config)")
        ),
        cli.verbose,
    );
    print_debug(
        &format!("Instance Name: {}", cli.instance_name),
        cli.verbose,
    );

    if cli.port_forward {
        print_debug(&format!("Mode: {}", "Port Forwarding".green()), cli.verbose);
        if let (Some(local_port), Some(remote_port)) = (cli.local_port, cli.remote_port) {
            print_debug(
                &format!(
                    "Port Mapping: localhost:{} -> {}:{}",
                    local_port, cli.remote_host, remote_port
                ),
                cli.verbose,
            );
        }
    } else {
        print_debug(
            &format!("Mode: {}", "Interactive Shell".green()),
            cli.verbose,
        );
    }

    if cli.verbose {
        eprintln!();
    }

    // Setup AWS configuration
    let config = get_aws_config(cli.profile.clone(), cli.region.clone()).await?;
    validate_aws_config(&config, cli.verbose).await?;

    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let ssm_client = aws_sdk_ssm::Client::new(&config);

    // Find instances
    let instances = find_instances_by_name(&ec2_client, &cli.instance_name, cli.verbose).await?;

    if instances.is_empty() {
        print_error(&format!(
            "No running instances found with Name tag: '{}'",
            cli.instance_name
        ));
        print_error("Please verify the instance name and ensure the instance is running.");
        std::process::exit(1);
    }

    let selected_instance = if instances.len() == 1 {
        print_success(&format!(
            "Found 1 instance with name: '{}'",
            cli.instance_name
        ));
        &instances[0]
    } else {
        select_instance(&instances)?
    };

    print_info(&format!(
        "Instance ID: {}",
        selected_instance.instance_id.green()
    ));

    // Check SSM availability
    check_ssm_availability(&ssm_client, &selected_instance.instance_id, cli.verbose).await?;

    // Record start time
    let start_instant = Instant::now();

    // Start SSM session
    start_ssm_session(
        &selected_instance.instance_id,
        cli.profile.clone(),
        cli.region.clone(),
        cli.port_forward,
        cli.local_port,
        cli.remote_port,
        &cli.remote_host,
    )
    .await?;

    // Calculate session duration
    let duration = start_instant.elapsed();

    // Create and display session summary (if not disabled)
    if !cli.no_summary {
        let summary = SessionSummary {
            instance_info: selected_instance.clone(),
            session_type: if cli.port_forward {
                "Port Forwarding".to_string()
            } else {
                "Interactive Shell".to_string()
            },
            local_port: cli.local_port,
            remote_port: cli.remote_port,
            remote_host: if cli.port_forward {
                Some(cli.remote_host)
            } else {
                None
            },
            duration,
            profile: cli.profile,
            region: cli.region,
        };

        print_session_summary(&summary);
    }

    Ok(())
}
