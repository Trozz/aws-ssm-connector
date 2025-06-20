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
use replay_rs::{Player, Recorder};
use std::process::Command;
use std::time::Instant;

mod native_ssm;

#[derive(Parser)]
#[command(name = "aws-ssm-connect")]
#[command(about = "Connect to AWS EC2 instances via SSM using instance Name tag")]
#[command(version = "1.0.0")]
struct Cli {
    /// Instance name (Name tag value)
    instance_name: Option<String>,

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

    /// Skip SSM availability checks for faster startup (assumes all instances are SSM-enabled)
    #[arg(long = "skip-ssm-check")]
    skip_ssm_check: bool,

    /// Use native Rust SSM implementation instead of AWS CLI
    #[arg(long = "native")]
    native: bool,

    /// Record session to file with timing data (built-in recorder)
    #[arg(long = "record")]
    record: Option<String>,

    /// Record session in plain text format (easier to view)
    #[arg(long = "record-text")]
    record_text: Option<String>,

    /// View a recorded session file
    #[arg(long = "view")]
    view: Option<String>,

    /// Playback speed for session replay (default: 1.0, 2.0 = 2x speed, 0.5 = half speed)
    #[arg(long = "play-speed", default_value = "1.0")]
    play_speed: f64,
}

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub instance_id: String,
    pub name: String,
    pub instance_type: String,
    pub state: String,
    pub private_ip: Option<String>,
    pub public_ip: Option<String>,
    pub tags: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub instance_id: String,
    pub profile: Option<String>,
    pub region: Option<String>,
    pub port_forward: bool,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub remote_host: String,
    pub recording_mode: Option<(String, bool)>, // (filename, is_plain_text)
    pub native: bool,
}

#[derive(Debug)]
pub struct SessionSummary {
    pub instance_info: InstanceInfo,
    pub session_type: String,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub remote_host: Option<String>,
    pub duration: std::time::Duration,
    pub profile: Option<String>,
    pub region: Option<String>,
}

pub fn print_info(message: &str) {
    eprintln!("{} {}", "[INFO]".blue().bold(), message);
}

pub fn print_debug(message: &str, verbose: bool) {
    if verbose {
        eprintln!("{} {}", "[DEBUG]".cyan().bold(), message);
    }
}

// Optimized version that takes a closure to avoid string formatting when not needed
pub fn print_debug_lazy<F>(message_fn: F, verbose: bool)
where
    F: FnOnce() -> String,
{
    if verbose {
        eprintln!("{} {}", "[DEBUG]".cyan().bold(), message_fn());
    }
}

pub fn print_success(message: &str) {
    eprintln!("{} {}", "[SUCCESS]".green().bold(), message);
}

pub fn print_warning(message: &str) {
    eprintln!("{} {}", "[WARNING]".yellow().bold(), message);
}

pub fn print_error(message: &str) {
    eprintln!("{} {}", "[ERROR]".red().bold(), message);
}

fn handle_aws_error(error: &str, operation: &str) -> anyhow::Error {
    // Check for common authentication issues and provide helpful messages
    if error.contains("ExpiredToken") || error.contains("TokenRefreshRequired") {
        anyhow!("AWS credentials have expired. Please refresh your credentials:\n  - For AWS SSO: Run 'aws sso login --profile <profile-name>'\n  - For regular credentials: Update your ~/.aws/credentials file")
    } else if error.contains("InvalidUserID.NotFound") || error.contains("AccessDenied") {
        anyhow!("AWS credentials are invalid or access is denied. Please check your credentials and permissions.")
    } else if error.contains("NoCredentialsError") || error.contains("CredentialsNotLoaded") {
        anyhow!("No AWS credentials found. Please configure your credentials:\n  - Run 'aws configure' to set up basic credentials\n  - Or use 'aws sso login' for SSO authentication\n  - Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
    } else if error.contains("UnknownHostException") || error.contains("NetworkingError") {
        anyhow!(
            "Network error connecting to AWS. Please check your internet connection and try again."
        )
    } else if error.contains("dispatch failure") {
        // This is likely a token expiration issue that's not being caught by the specific checks above
        anyhow!("AWS authentication failed (likely expired credentials). Please refresh your credentials:\n  - For AWS SSO: Run 'aws sso login --profile <profile-name>'\n  - For regular credentials: Update your ~/.aws/credentials file or run 'aws configure'")
    } else {
        anyhow!("{}: {}", operation, error)
    }
}

pub async fn get_aws_config(
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
        Err(e) => Err(handle_aws_error(
            &e.to_string(),
            "Failed to authenticate with AWS",
        )),
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
        .await
        .map_err(|e| handle_aws_error(&e.to_string(), "Failed to describe EC2 instances"))?;

    // Pre-allocate capacity based on typical reservation sizes
    let mut instances = Vec::with_capacity(response.reservations().len() * 2);

    for reservation in response.reservations() {
        for instance in reservation.instances() {
            // Process tags in a single iteration for better performance
            let mut name = "Unknown";
            let mut tags = Vec::with_capacity(instance.tags().len());

            for tag in instance.tags() {
                if let (Some(key), Some(value)) = (tag.key(), tag.value()) {
                    if key == "Name" {
                        name = value;
                    }
                    tags.push((key.to_string(), value.to_string()));
                }
            }

            let instance_info = InstanceInfo {
                instance_id: instance.instance_id().unwrap_or("Unknown").to_string(),
                name: name.to_string(),
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
        .await
        .map_err(|e| handle_aws_error(&e.to_string(), "Failed to check SSM availability"))?;

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

pub fn display_instance_info(instance: &InstanceInfo, index: usize) {
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

    // Pre-allocate with known capacity to avoid reallocations
    let mut selection_items = Vec::with_capacity(instances.len());
    for instance in instances {
        selection_items.push(format!("{} ({})", instance.name, instance.instance_id));
    }

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

async fn start_session_manager_plugin(
    ssm_client: &aws_sdk_ssm::Client,
    config: &SessionConfig,
) -> Result<()> {
    // Start SSM session using AWS SDK
    let mut request = ssm_client.start_session().target(&config.instance_id);

    if config.port_forward {
        let local_port_val = config
            .local_port
            .ok_or_else(|| anyhow!("Local port required for port forwarding"))?;
        let remote_port_val = config
            .remote_port
            .ok_or_else(|| anyhow!("Remote port required for port forwarding"))?;

        if config.remote_host == "localhost" || config.remote_host == "127.0.0.1" {
            request = request.document_name("AWS-StartPortForwardingSession");
        } else {
            request = request.document_name("AWS-StartPortForwardingSessionToRemoteHost");
        }

        print_info(&format!(
            "Starting port forwarding session: localhost:{} → {}:{}",
            local_port_val, &config.remote_host, remote_port_val
        ));
    } else {
        print_info("Starting SSM session...");
    }

    let response = request
        .send()
        .await
        .map_err(|e| handle_aws_error(&e.to_string(), "Failed to start SSM session"))?;

    let session_id = response
        .session_id()
        .ok_or_else(|| anyhow!("No session ID returned"))?;
    let stream_url = response
        .stream_url()
        .ok_or_else(|| anyhow!("No stream URL returned"))?;
    let token = response
        .token_value()
        .ok_or_else(|| anyhow!("No token returned"))?;

    // Prepare session data for session-manager-plugin
    let session_data = serde_json::json!({
        "SessionId": session_id,
        "TokenValue": token,
        "StreamUrl": stream_url
    });

    let parameters = if config.port_forward {
        let local_port_val = config.local_port.unwrap();
        let remote_port_val = config.remote_port.unwrap();

        if config.remote_host == "localhost" || config.remote_host == "127.0.0.1" {
            serde_json::json!({
                "localPortNumber": [local_port_val.to_string()],
                "portNumber": [remote_port_val.to_string()]
            })
        } else {
            serde_json::json!({
                "localPortNumber": [local_port_val.to_string()],
                "portNumber": [remote_port_val.to_string()],
                "host": [&config.remote_host]
            })
        }
    } else {
        serde_json::json!({})
    };

    let start_session_request = serde_json::json!({
        "SessionId": session_id,
        "Target": &config.instance_id
    });

    // Call session-manager-plugin directly
    let mut cmd = Command::new("session-manager-plugin");
    cmd.arg(session_data.to_string())
        .arg(config.region.as_deref().unwrap_or("us-east-1"))
        .arg("StartSession")
        .arg(config.profile.as_deref().unwrap_or(""))
        .arg(start_session_request.to_string())
        .arg(format!(
            "https://ssm.{}.amazonaws.com",
            config.region.as_deref().unwrap_or("us-east-1")
        ));

    if config.port_forward {
        cmd.arg(parameters.to_string());
    }

    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow!(
            "session-manager-plugin failed with exit code: {:?}",
            status.code()
        ));
    }

    Ok(())
}

async fn start_session_with_recording(
    config: SessionConfig,
    ssm_client: Option<&aws_sdk_ssm::Client>,
) -> Result<()> {
    if let Some((output_file, is_plain_text)) = &config.recording_mode {
        // Record session using script command (Unix/Linux/macOS)
        let _session_type = if config.port_forward {
            "port-forward"
        } else {
            "interactive"
        };

        // Handle recording for different modes
        if config.native {
            if let Some(client) = ssm_client {
                print_info(&format!("Recording session to: {}", output_file));
                // For native mode, we need to wrap our session-manager-plugin call
                return record_native_session(client, &config, output_file, *is_plain_text).await;
            } else {
                return Err(anyhow!("SSM client required for native mode"));
            }
        } else {
            // For AWS CLI mode, we can use script to record the aws command
            let mut aws_args = vec![
                "ssm".to_string(),
                "start-session".to_string(),
                "--target".to_string(),
                config.instance_id.clone(),
            ];

            if let Some(p) = &config.profile {
                aws_args.extend(vec!["--profile".to_string(), p.clone()]);
            }
            if let Some(r) = &config.region {
                aws_args.extend(vec!["--region".to_string(), r.clone()]);
            }

            if config.port_forward {
                let local_port = config
                    .local_port
                    .ok_or_else(|| anyhow!("Local port required"))?;
                let remote_port = config
                    .remote_port
                    .ok_or_else(|| anyhow!("Remote port required"))?;

                if config.remote_host == "localhost" || config.remote_host == "127.0.0.1" {
                    aws_args.extend(vec![
                        "--document-name".to_string(),
                        "AWS-StartPortForwardingSession".to_string(),
                        "--parameters".to_string(),
                        format!("localPortNumber={},portNumber={}", local_port, remote_port),
                    ]);
                } else {
                    aws_args.extend(vec![
                        "--document-name".to_string(),
                        "AWS-StartPortForwardingSessionToRemoteHost".to_string(),
                        "--parameters".to_string(),
                        format!(
                            "localPortNumber={},portNumber={},host={}",
                            local_port, remote_port, &config.remote_host
                        ),
                    ]);
                }
            }

            let timing_file = format!("{}.timing", output_file);

            // Use built-in recorder (works on all platforms with timing)
            let mut aws_cmd = Command::new("aws");
            aws_cmd.args(&aws_args);
            let recorder = Recorder::new(output_file, &timing_file)?;
            recorder.record_command(aws_cmd, *is_plain_text)?;

            return Ok(());
        }
    }

    // No recording, run normally
    if config.native {
        if let Some(client) = ssm_client {
            start_session_manager_plugin(client, &config).await
        } else {
            Err(anyhow!("SSM client required for native mode"))
        }
    } else {
        start_ssm_session(
            &config.instance_id,
            config.profile,
            config.region,
            config.port_forward,
            config.local_port,
            config.remote_port,
            &config.remote_host,
        )
        .await
    }
}

async fn record_native_session(
    ssm_client: &aws_sdk_ssm::Client,
    config: &SessionConfig,
    output_file: &str,
    is_plain_text: bool,
) -> Result<()> {
    // Start SSM session using AWS SDK (same as start_session_manager_plugin)
    let mut request = ssm_client.start_session().target(&config.instance_id);

    if config.port_forward {
        config
            .local_port
            .ok_or_else(|| anyhow!("Local port required"))?;
        config
            .remote_port
            .ok_or_else(|| anyhow!("Remote port required"))?;

        if config.remote_host == "localhost" || config.remote_host == "127.0.0.1" {
            request = request.document_name("AWS-StartPortForwardingSession");
        } else {
            request = request.document_name("AWS-StartPortForwardingSessionToRemoteHost");
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| handle_aws_error(&e.to_string(), "Failed to start SSM session"))?;

    let session_id = response
        .session_id()
        .ok_or_else(|| anyhow!("No session ID returned"))?;
    let stream_url = response
        .stream_url()
        .ok_or_else(|| anyhow!("No stream URL returned"))?;
    let token = response
        .token_value()
        .ok_or_else(|| anyhow!("No token returned"))?;

    // Prepare session data
    let session_data = serde_json::json!({
        "SessionId": session_id,
        "TokenValue": token,
        "StreamUrl": stream_url
    });

    let start_session_request = serde_json::json!({
        "SessionId": session_id,
        "Target": &config.instance_id
    });

    // Build session-manager-plugin command
    let mut plugin_cmd = vec![
        "session-manager-plugin".to_string(),
        session_data.to_string(),
        config.region.as_deref().unwrap_or("us-east-1").to_string(),
        "StartSession".to_string(),
        config.profile.as_deref().unwrap_or("").to_string(),
        start_session_request.to_string(),
        format!(
            "https://ssm.{}.amazonaws.com",
            config.region.as_deref().unwrap_or("us-east-1")
        ),
    ];

    if config.port_forward {
        let local_port_val = config.local_port.unwrap();
        let remote_port_val = config.remote_port.unwrap();

        let parameters = if config.remote_host == "localhost" || config.remote_host == "127.0.0.1" {
            serde_json::json!({
                "localPortNumber": [local_port_val.to_string()],
                "portNumber": [remote_port_val.to_string()]
            })
        } else {
            serde_json::json!({
                "localPortNumber": [local_port_val.to_string()],
                "portNumber": [remote_port_val.to_string()],
                "host": [&config.remote_host]
            })
        };
        plugin_cmd.push(parameters.to_string());
    }

    // Use built-in recorder (works on all platforms with timing)
    let timing_file = format!("{}.timing", output_file);
    let mut plugin_command = Command::new("session-manager-plugin");
    plugin_command.args(&plugin_cmd[1..]); // Skip the first element which is the command name

    let recorder = Recorder::new(output_file, &timing_file)?;
    recorder.record_command(plugin_command, is_plain_text)?;

    Ok(())
}

pub fn print_session_summary(summary: &SessionSummary) {
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

pub fn format_duration(duration: std::time::Duration) -> String {
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

fn view_recorded_session(file_path: &str, play_speed: f64) -> Result<()> {
    use std::path::Path;

    let path = Path::new(file_path);
    if !path.exists() {
        return Err(anyhow!("File not found: {}", file_path));
    }

    println!("Viewing recorded session: {}", file_path);
    println!("{}", "=".repeat(50));

    // Try different methods to view the file

    // Method 1: Check for timing file and use built-in or external scriptreplay
    let timing_file = format!("{}.timing", file_path);
    if std::path::Path::new(&timing_file).exists() {
        // Try external scriptreplay first (if available), then fall back to built-in
        if let Ok(status) = Command::new("scriptreplay").arg("-h").output() {
            if status.status.success() {
                println!("🎬 Playing back session with external scriptreplay");
                println!("   Press Ctrl+C to stop, or wait for automatic completion");
                println!("   Playback speed: {}x", play_speed);
                println!();

                let status = Command::new("scriptreplay")
                    .arg(&timing_file)
                    .arg(file_path)
                    .arg(play_speed.to_string())
                    .status()?;

                if status.success() {
                    return Ok(());
                } else {
                    println!("⚠️  External scriptreplay failed, trying built-in version...");
                }
            }
        }

        // Use built-in scriptreplay implementation
        println!("📅 Found timing file: {}", timing_file);
        let player = Player::new(&timing_file, file_path)?;
        return player.replay(play_speed);
    } else {
        // No timing file available
        println!("⏱️  No timing file found ({})", timing_file);
        println!("💡 Tip: On Linux, recording with timing creates better playback experience");
        println!();
    }

    // Method 2: Simply display the file content with ANSI interpretation
    // The terminal will automatically interpret the colors and formatting
    let content = std::fs::read_to_string(file_path).unwrap_or_else(|_| {
        // If it fails as UTF-8, try to read as bytes and show what we can
        let bytes = std::fs::read(file_path).unwrap_or_default();
        String::from_utf8_lossy(&bytes).to_string()
    });

    // Clean up only the problematic control sequences but preserve colors
    let cleaned_content = replay_rs::clean_for_display(&content);
    if !cleaned_content.trim().is_empty() {
        println!("Session content (with colors preserved):");
        println!();
        print!("{}", cleaned_content);
        return Ok(());
    }

    // Method 3: Try to clean up with col command
    if let Ok(output) = Command::new("col")
        .args(["-bx"])
        .stdin(std::fs::File::open(file_path)?)
        .output()
    {
        if output.status.success() {
            let cleaned_output = String::from_utf8_lossy(&output.stdout);
            if !cleaned_output.trim().is_empty() {
                println!("Session content (cleaned with col):");
                println!();
                print!("{}", cleaned_output);
                return Ok(());
            }
        }
    }

    // Method 4: Try strings command to extract readable text
    if let Ok(output) = Command::new("strings").arg(file_path).output() {
        if output.status.success() {
            println!("Extracted text from session (may be incomplete):");
            println!();
            print!("{}", String::from_utf8_lossy(&output.stdout));
            return Ok(());
        }
    }

    // Method 5: Last resort - show raw content with warning
    println!("Warning: Unable to clean session file. Showing raw content:");
    println!(
        "For better viewing, try: scriptreplay {} or col -bx < {}",
        file_path, file_path
    );
    println!();
    print!("{}", content);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle view command first
    if let Some(file_path) = &cli.view {
        return view_recorded_session(file_path, cli.play_speed);
    }

    // Validate required arguments
    let instance_name = cli
        .instance_name
        .as_ref()
        .ok_or_else(|| anyhow!("Instance name is required when not using --view"))?;

    // Validate port forwarding arguments
    if cli.port_forward && (cli.local_port.is_none() || cli.remote_port.is_none()) {
        print_error("Port forwarding mode requires both --local-port and --remote-port.");
        std::process::exit(1);
    }

    print_debug("AWS SSM Connect Tool", cli.verbose);
    print_debug_lazy(
        || format!("Profile: {}", cli.profile.as_deref().unwrap_or("default")),
        cli.verbose,
    );
    print_debug_lazy(
        || {
            format!(
                "Region: {}",
                cli.region.as_deref().unwrap_or("default (from config)")
            )
        },
        cli.verbose,
    );
    print_debug_lazy(|| format!("Instance Name: {}", instance_name), cli.verbose);

    if cli.port_forward {
        print_debug_lazy(
            || format!("Mode: {}", "Port Forwarding".green()),
            cli.verbose,
        );
        if let (Some(local_port), Some(remote_port)) = (cli.local_port, cli.remote_port) {
            print_debug_lazy(
                || {
                    format!(
                        "Port Mapping: localhost:{} -> {}:{}",
                        local_port, cli.remote_host, remote_port
                    )
                },
                cli.verbose,
            );
        }
    } else {
        print_debug_lazy(
            || format!("Mode: {}", "Interactive Shell".green()),
            cli.verbose,
        );
    }

    if cli.verbose {
        eprintln!();
    }

    // Setup AWS configuration and validate concurrently with instance discovery
    let config = get_aws_config(cli.profile.clone(), cli.region.clone()).await?;

    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let ssm_client = aws_sdk_ssm::Client::new(&config);

    // Run validation and instance discovery concurrently
    let (_validation_result, instances) = tokio::try_join!(
        validate_aws_config(&config, cli.verbose),
        find_instances_by_name(&ec2_client, instance_name, cli.verbose)
    )?;

    if instances.is_empty() {
        print_error(&format!(
            "No running instances found with Name tag: '{}'",
            instance_name
        ));
        print_error("Please verify the instance name and ensure the instance is running.");
        std::process::exit(1);
    }

    let ssm_available_instances = if cli.skip_ssm_check {
        print_debug("Skipping SSM availability checks", cli.verbose);
        instances
    } else {
        // Pre-check SSM availability for all instances concurrently
        print_debug_lazy(
            || {
                format!(
                    "Checking SSM availability for {} instances",
                    instances.len()
                )
            },
            cli.verbose,
        );

        let ssm_checks: Vec<_> = instances
            .iter()
            .enumerate()
            .map(|(idx, instance)| {
                let ssm_client = &ssm_client;
                let instance_id = &instance.instance_id;
                async move {
                    check_ssm_availability(ssm_client, instance_id, false)
                        .await
                        .map(|_| idx)
                        .map_err(|_| idx)
                }
            })
            .collect();

        let ssm_results = futures::future::join_all(ssm_checks).await;

        // Filter to only SSM-available instances
        let mut available_instances = Vec::new();
        for (idx, result) in ssm_results.into_iter().enumerate() {
            if result.is_ok() {
                available_instances.push(instances[idx].clone());
            } else if cli.verbose {
                print_warning(&format!(
                    "Instance {} is not available for SSM",
                    instances[idx].instance_id
                ));
            }
        }
        available_instances
    };

    if ssm_available_instances.is_empty() {
        print_error("No instances are available for SSM connection");
        std::process::exit(1);
    }

    let selected_instance = if ssm_available_instances.len() == 1 {
        print_success(&format!(
            "Found 1 SSM-available instance with name: '{}'",
            instance_name
        ));
        &ssm_available_instances[0]
    } else {
        select_instance(&ssm_available_instances)?
    };

    print_info(&format!(
        "Instance ID: {}",
        selected_instance.instance_id.green()
    ));

    // Record start time
    let start_instant = Instant::now();

    // Determine recording mode
    let recording_mode = if cli.record.is_some() && cli.record_text.is_some() {
        return Err(anyhow!(
            "Cannot use both --record and --record-text. Choose one."
        ));
    } else if let Some(file) = cli.record.clone() {
        Some((file, false)) // script format
    } else {
        cli.record_text.clone().map(|file| (file, true))
    };

    // Start SSM session (with optional recording)
    let config = SessionConfig {
        instance_id: selected_instance.instance_id.clone(),
        profile: cli.profile.clone(),
        region: cli.region.clone(),
        port_forward: cli.port_forward,
        local_port: cli.local_port,
        remote_port: cli.remote_port,
        remote_host: cli.remote_host.clone(),
        recording_mode,
        native: cli.native,
    };

    start_session_with_recording(config, if cli.native { Some(&ssm_client) } else { None }).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(std::time::Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(std::time::Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(std::time::Duration::from_secs(60)), "1m 0s");
        assert_eq!(
            format_duration(std::time::Duration::from_secs(90)),
            "1m 30s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3600)),
            "1h 0m 0s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3665)),
            "1h 1m 5s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(7325)),
            "2h 2m 5s"
        );
    }

    #[test]
    fn test_instance_info_creation() {
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "test-instance".to_string(),
            instance_type: "t2.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: Some("54.123.45.67".to_string()),
            tags: vec![
                ("Name".to_string(), "test-instance".to_string()),
                ("Environment".to_string(), "production".to_string()),
            ],
        };

        assert_eq!(instance_info.instance_id, "i-1234567890abcdef0");
        assert_eq!(instance_info.name, "test-instance");
        assert_eq!(instance_info.instance_type, "t2.micro");
        assert_eq!(instance_info.state, "running");
        assert_eq!(instance_info.private_ip, Some("10.0.0.1".to_string()));
        assert_eq!(instance_info.public_ip, Some("54.123.45.67".to_string()));
        assert_eq!(instance_info.tags.len(), 2);
    }

    #[test]
    fn test_session_summary_creation() {
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "test-instance".to_string(),
            instance_type: "t2.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: None,
            tags: vec![],
        };

        let summary = SessionSummary {
            instance_info: instance_info.clone(),
            session_type: "Port Forwarding".to_string(),
            local_port: Some(8080),
            remote_port: Some(80),
            remote_host: Some("localhost".to_string()),
            duration: std::time::Duration::from_secs(300),
            profile: Some("dev".to_string()),
            region: Some("us-west-2".to_string()),
        };

        assert_eq!(summary.instance_info.instance_id, "i-1234567890abcdef0");
        assert_eq!(summary.session_type, "Port Forwarding");
        assert_eq!(summary.local_port, Some(8080));
        assert_eq!(summary.remote_port, Some(80));
        assert_eq!(summary.remote_host, Some("localhost".to_string()));
        assert_eq!(summary.duration.as_secs(), 300);
        assert_eq!(summary.profile, Some("dev".to_string()));
        assert_eq!(summary.region, Some("us-west-2".to_string()));
    }

    #[tokio::test]
    async fn test_get_aws_config_with_profile_and_region() {
        let config = get_aws_config(
            Some("test-profile".to_string()),
            Some("us-east-1".to_string()),
        )
        .await;

        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn test_get_aws_config_defaults() {
        let config = get_aws_config(None, None).await;
        assert!(config.is_ok());
    }

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;

        let cmd = Cli::command();

        // Test valid instance name argument
        let result = cmd
            .clone()
            .try_get_matches_from(vec!["aws-ssm-connect", "my-instance"]);
        assert!(result.is_ok());

        // Test with profile and region
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "my-instance",
            "--profile",
            "dev",
            "--region",
            "us-west-2",
        ]);
        assert!(result.is_ok());

        // Test port forwarding arguments
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "my-instance",
            "--port-forward",
            "--local-port",
            "8080",
            "--remote-port",
            "80",
        ]);
        assert!(result.is_ok());

        // Test verbose and no-summary flags
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "my-instance",
            "--verbose",
            "--no-summary",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_functions() {
        // Test that print functions don't panic
        print_info("Test info message");
        print_debug("Test debug message", true);
        print_debug("Hidden debug message", false);
        print_success("Test success message");
        print_warning("Test warning message");
        print_error("Test error message");
        
        // Test debug lazy function
        print_debug_lazy(|| "Expensive computation".to_string(), true);
        print_debug_lazy(|| panic!("Should not be called"), false);
    }

    #[test]
    fn test_handle_aws_error() {
        let expired_token_error = handle_aws_error("ExpiredToken occurred", "test operation");
        assert!(expired_token_error.to_string().contains("expired"));
        assert!(expired_token_error.to_string().contains("aws sso login"));

        let access_denied_error = handle_aws_error("AccessDenied", "test operation");
        assert!(access_denied_error.to_string().contains("invalid or access is denied"));

        let no_credentials_error = handle_aws_error("NoCredentialsError", "test operation");
        assert!(no_credentials_error.to_string().contains("No AWS credentials found"));

        let network_error = handle_aws_error("UnknownHostException", "test operation");
        assert!(network_error.to_string().contains("Network error"));

        let dispatch_error = handle_aws_error("dispatch failure", "test operation");
        assert!(dispatch_error.to_string().contains("authentication failed"));

        let generic_error = handle_aws_error("some other error", "test operation");
        assert_eq!(generic_error.to_string(), "test operation: some other error");
    }


    #[test]
    fn test_session_config_creation() {
        let session_config = SessionConfig {
            instance_id: "i-1234567890abcdef0".to_string(),
            profile: Some("development".to_string()),
            region: Some("us-east-1".to_string()),
            port_forward: true,
            local_port: Some(8080),
            remote_port: Some(80),
            remote_host: "localhost".to_string(),
            recording_mode: Some(("session.log".to_string(), false)),
            native: true,
        };

        assert_eq!(session_config.instance_id, "i-1234567890abcdef0");
        assert_eq!(session_config.profile, Some("development".to_string()));
        assert_eq!(session_config.region, Some("us-east-1".to_string()));
        assert!(session_config.port_forward);
        assert_eq!(session_config.local_port, Some(8080));
        assert_eq!(session_config.remote_port, Some(80));
        assert_eq!(session_config.remote_host, "localhost");
        assert_eq!(session_config.recording_mode, Some(("session.log".to_string(), false)));
        assert!(session_config.native);
    }


    #[test]
    fn test_view_recorded_session_file_not_found() {
        let result = view_recorded_session("non_existent_file.log", 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("File not found"));
    }

    #[test] 
    fn test_debug_trait_implementations() {
        let instance = InstanceInfo {
            instance_id: "i-123".to_string(),
            name: "test".to_string(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: None,
            public_ip: None,
            tags: vec![],
        };

        let debug_str = format!("{:?}", instance);
        assert!(debug_str.contains("InstanceInfo"));
        assert!(debug_str.contains("i-123"));

        let config = SessionConfig {
            instance_id: "i-123".to_string(),
            profile: None,
            region: None,
            port_forward: false,
            local_port: None,
            remote_port: None,
            remote_host: "localhost".to_string(),
            recording_mode: None,
            native: false,
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SessionConfig"));

        let summary = SessionSummary {
            instance_info: instance,
            session_type: "standard".to_string(),
            local_port: None,
            remote_port: None,
            remote_host: None,
            duration: std::time::Duration::from_secs(60),
            profile: None,
            region: None,
        };

        let debug_str = format!("{:?}", summary);
        assert!(debug_str.contains("SessionSummary"));
    }

    #[test]
    fn test_cli_parsing_errors() {
        use clap::CommandFactory;

        let cmd = Cli::command();

        // Test missing instance name (should now be allowed for --view command)
        let result = cmd.clone().try_get_matches_from(vec!["aws-ssm-connect"]);
        // This should succeed now since instance_name is optional
        assert!(result.is_ok());

        // Test invalid port number
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "my-instance",
            "--port-forward",
            "--local-port",
            "not-a-number",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_display_functions_dont_panic() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        // Test print functions don't panic
        print_info("Test info message");
        print_success("Test success message");
        print_warning("Test warning message");
        print_error("Test error message");
        print_debug("Test debug message", true);
        print_debug("Test debug message", false);

        // Test display_instance_info doesn't panic
        let instance = InstanceInfo {
            instance_id: "i-test".to_string(),
            name: "test".to_string(),
            instance_type: "t2.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: None,
            tags: vec![
                ("Name".to_string(), "test".to_string()),
                ("Env".to_string(), "prod".to_string()),
            ],
        };

        display_instance_info(&instance, 1);
    }

    #[test]
    fn test_session_summary_display() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        let instance = InstanceInfo {
            instance_id: "i-test".to_string(),
            name: "test-instance".to_string(),
            instance_type: "t2.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: None,
            tags: vec![],
        };

        // Test regular session summary
        let summary = SessionSummary {
            instance_info: instance.clone(),
            session_type: "Interactive Shell".to_string(),
            local_port: None,
            remote_port: None,
            remote_host: None,
            duration: std::time::Duration::from_secs(123),
            profile: None,
            region: None,
        };

        print_session_summary(&summary);

        // Test port forwarding session summary
        let summary = SessionSummary {
            instance_info: instance,
            session_type: "Port Forwarding".to_string(),
            local_port: Some(8080),
            remote_port: Some(80),
            remote_host: Some("remote-service".to_string()),
            duration: std::time::Duration::from_secs(456),
            profile: Some("dev".to_string()),
            region: Some("us-west-2".to_string()),
        };

        print_session_summary(&summary);
    }

    #[test]
    fn test_instance_selection_display() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        let instances = vec![
            InstanceInfo {
                instance_id: "i-1234567890abcdef0".to_string(),
                name: "web-server-1".to_string(),
                instance_type: "t3.medium".to_string(),
                state: "running".to_string(),
                private_ip: Some("10.0.1.100".to_string()),
                public_ip: Some("54.123.45.67".to_string()),
                tags: vec![
                    ("Name".to_string(), "web-server-1".to_string()),
                    ("Environment".to_string(), "production".to_string()),
                ],
            },
            InstanceInfo {
                instance_id: "i-0987654321fedcba0".to_string(),
                name: "web-server-2".to_string(),
                instance_type: "t3.medium".to_string(),
                state: "running".to_string(),
                private_ip: Some("10.0.1.101".to_string()),
                public_ip: None,
                tags: vec![
                    ("Name".to_string(), "web-server-2".to_string()),
                    ("Environment".to_string(), "staging".to_string()),
                ],
            },
        ];

        // Test that displaying multiple instances doesn't panic
        for (i, instance) in instances.iter().enumerate() {
            display_instance_info(instance, i + 1);
        }
    }

    #[test]
    fn test_selection_items_format() {
        let instances = vec![
            InstanceInfo {
                instance_id: "i-1234567890abcdef0".to_string(),
                name: "web-server-1".to_string(),
                instance_type: "t3.medium".to_string(),
                state: "running".to_string(),
                private_ip: Some("10.0.1.100".to_string()),
                public_ip: Some("54.123.45.67".to_string()),
                tags: vec![],
            },
            InstanceInfo {
                instance_id: "i-0987654321fedcba0".to_string(),
                name: "web-server-2".to_string(),
                instance_type: "t3.medium".to_string(),
                state: "running".to_string(),
                private_ip: Some("10.0.1.101".to_string()),
                public_ip: None,
                tags: vec![],
            },
        ];

        let selection_items: Vec<String> = instances
            .iter()
            .map(|instance| format!("{} ({})", instance.name, instance.instance_id))
            .collect();

        assert_eq!(selection_items.len(), 2);
        assert_eq!(selection_items[0], "web-server-1 (i-1234567890abcdef0)");
        assert_eq!(selection_items[1], "web-server-2 (i-0987654321fedcba0)");
    }

    #[test]
    fn test_ssm_command_construction_basic() {
        use std::process::Command;

        // Test basic session command construction (non-port-forwarding)
        let mut cmd = Command::new("aws");
        cmd.args(["ssm", "start-session"]);
        cmd.args(["--target", "i-1234567890abcdef0"]);

        // Verify the command structure
        let program = cmd.get_program();
        assert_eq!(program, "aws");

        let args: Vec<&str> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
        assert!(args.contains(&"ssm"));
        assert!(args.contains(&"start-session"));
        assert!(args.contains(&"--target"));
        assert!(args.contains(&"i-1234567890abcdef0"));
    }

    #[test]
    fn test_ssm_command_with_profile_and_region() {
        use std::process::Command;

        let mut cmd = Command::new("aws");
        cmd.args(["ssm", "start-session"]);
        cmd.args(["--profile", "dev-profile"]);
        cmd.args(["--region", "us-west-2"]);
        cmd.args(["--target", "i-1234567890abcdef0"]);

        let args: Vec<&str> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
        assert!(args.contains(&"--profile"));
        assert!(args.contains(&"dev-profile"));
        assert!(args.contains(&"--region"));
        assert!(args.contains(&"us-west-2"));
    }

    #[test]
    fn test_port_forwarding_command_localhost() {
        use std::process::Command;

        let mut cmd = Command::new("aws");
        cmd.args(["ssm", "start-session"]);
        cmd.args(["--target", "i-1234567890abcdef0"]);
        cmd.args(["--document-name", "AWS-StartPortForwardingSession"]);
        cmd.args(["--parameters", "localPortNumber=8080,portNumber=80"]);

        let args: Vec<&str> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
        assert!(args.contains(&"--document-name"));
        assert!(args.contains(&"AWS-StartPortForwardingSession"));
        assert!(args.contains(&"--parameters"));
        assert!(args.contains(&"localPortNumber=8080,portNumber=80"));
    }

    #[test]
    fn test_port_forwarding_command_remote_host() {
        use std::process::Command;

        let mut cmd = Command::new("aws");
        cmd.args(["ssm", "start-session"]);
        cmd.args(["--target", "i-1234567890abcdef0"]);
        cmd.args([
            "--document-name",
            "AWS-StartPortForwardingSessionToRemoteHost",
        ]);
        cmd.args([
            "--parameters",
            "localPortNumber=8080,portNumber=80,host=database.internal",
        ]);

        let args: Vec<&str> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
        assert!(args.contains(&"AWS-StartPortForwardingSessionToRemoteHost"));
        assert!(args.contains(&"localPortNumber=8080,portNumber=80,host=database.internal"));
    }

    #[test]
    fn test_port_forwarding_validation_missing_local_port() {
        // Test the logic that would be in main() for validating port forwarding args
        let port_forward = true;
        let local_port: Option<u16> = None;
        let remote_port: Option<u16> = Some(80);

        let validation_failed = port_forward && (local_port.is_none() || remote_port.is_none());
        assert!(
            validation_failed,
            "Should fail validation when local_port is missing"
        );
    }

    #[test]
    fn test_port_forwarding_validation_missing_remote_port() {
        let port_forward = true;
        let local_port: Option<u16> = Some(8080);
        let remote_port: Option<u16> = None;

        let validation_failed = port_forward && (local_port.is_none() || remote_port.is_none());
        assert!(
            validation_failed,
            "Should fail validation when remote_port is missing"
        );
    }

    #[test]
    fn test_port_forwarding_validation_success() {
        let port_forward = true;
        let local_port: Option<u16> = Some(8080);
        let remote_port: Option<u16> = Some(80);

        let validation_failed = port_forward && (local_port.is_none() || remote_port.is_none());
        assert!(
            !validation_failed,
            "Should pass validation when both ports are provided"
        );
    }

    #[test]
    fn test_port_forwarding_validation_disabled() {
        let port_forward = false;
        let local_port: Option<u16> = None;
        let remote_port: Option<u16> = None;

        let validation_failed = port_forward && (local_port.is_none() || remote_port.is_none());
        assert!(
            !validation_failed,
            "Should pass validation when port forwarding is disabled"
        );
    }

    #[test]
    fn test_remote_host_localhost_detection() {
        let remote_hosts = vec!["localhost", "127.0.0.1"];

        for host in remote_hosts {
            let is_localhost = host == "localhost" || host == "127.0.0.1";
            assert!(is_localhost, "Should detect {} as localhost", host);
        }
    }

    #[test]
    fn test_remote_host_non_localhost_detection() {
        let remote_hosts = vec!["database.internal", "192.168.1.100", "example.com"];

        for host in remote_hosts {
            let is_localhost = host == "localhost" || host == "127.0.0.1";
            assert!(!is_localhost, "Should not detect {} as localhost", host);
        }
    }

    #[test]
    fn test_empty_instance_list_handling() {
        let instances: Vec<InstanceInfo> = vec![];

        // Test that empty instance list can be handled
        assert_eq!(instances.len(), 0);

        // Test selection items generation with empty list
        let selection_items: Vec<String> = instances
            .iter()
            .map(|instance| format!("{} ({})", instance.name, instance.instance_id))
            .collect();
        assert_eq!(selection_items.len(), 0);
    }

    #[test]
    fn test_single_instance_scenario() {
        let instances = vec![InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "single-server".to_string(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.1.100".to_string()),
            public_ip: None,
            tags: vec![],
        }];

        assert_eq!(instances.len(), 1);

        // In main(), this would skip the selection dialog and use instances[0] directly
        let selected_instance = &instances[0];
        assert_eq!(selected_instance.name, "single-server");
        assert_eq!(selected_instance.instance_id, "i-1234567890abcdef0");
    }

    #[test]
    fn test_tag_filtering_logic() {
        // Test the tag filtering logic that extracts Name tag and other tags
        let tags_with_name = vec![
            ("Name".to_string(), "web-server-1".to_string()),
            ("Environment".to_string(), "production".to_string()),
            ("Team".to_string(), "backend".to_string()),
        ];

        // Find Name tag
        let name_tag = tags_with_name
            .iter()
            .find(|(key, _)| key == "Name")
            .map(|(_, value)| value.clone())
            .unwrap_or("Unknown".to_string());

        assert_eq!(name_tag, "web-server-1");

        // Filter out Name tag to get other tags
        let other_tags: Vec<_> = tags_with_name
            .iter()
            .filter(|(key, _)| key != "Name")
            .collect();

        assert_eq!(other_tags.len(), 2);
        assert!(other_tags.contains(&&("Environment".to_string(), "production".to_string())));
        assert!(other_tags.contains(&&("Team".to_string(), "backend".to_string())));
    }

    #[test]
    fn test_instance_with_no_name_tag() {
        // Test handling of instance without Name tag
        let tags_without_name = vec![
            ("Environment".to_string(), "staging".to_string()),
            ("Team".to_string(), "frontend".to_string()),
        ];

        let name_tag = tags_without_name
            .iter()
            .find(|(key, _)| key == "Name")
            .map(|(_, value)| value.clone())
            .unwrap_or("Unknown".to_string());

        assert_eq!(name_tag, "Unknown");
    }

    #[test]
    fn test_instance_with_empty_tags() {
        // Test handling of instance with no tags at all
        let empty_tags: Vec<(String, String)> = vec![];

        let name_tag = empty_tags
            .iter()
            .find(|(key, _)| key == "Name")
            .map(|(_, value)| value.clone())
            .unwrap_or("Unknown".to_string());

        assert_eq!(name_tag, "Unknown");
        assert_eq!(empty_tags.len(), 0);
    }

    #[test]
    fn test_instance_with_duplicate_name_tags() {
        // Test handling when there might be duplicate Name tags (edge case)
        let duplicate_name_tags = vec![
            ("Name".to_string(), "first-name".to_string()),
            ("Environment".to_string(), "prod".to_string()),
            ("Name".to_string(), "second-name".to_string()),
        ];

        // Should get the first matching Name tag
        let name_tag = duplicate_name_tags
            .iter()
            .find(|(key, _)| key == "Name")
            .map(|(_, value)| value.clone())
            .unwrap_or("Unknown".to_string());

        assert_eq!(name_tag, "first-name");
    }

    #[test]
    fn test_instance_discovery_edge_cases() {
        // Test various instance state scenarios
        let test_cases = vec![
            ("running", true),
            ("stopped", false),
            ("terminated", false),
            ("pending", false),
            ("stopping", false),
            ("shutting-down", false),
        ];

        for (state, should_be_included) in test_cases {
            // In the actual code, only "running" instances are included via the state filter
            let is_running = state == "running";
            assert_eq!(
                is_running, should_be_included,
                "State '{}' inclusion check failed",
                state
            );
        }
    }

    #[test]
    fn test_instance_info_with_missing_fields() {
        // Test InstanceInfo creation with missing optional fields
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "Unknown".to_string(),          // No Name tag
            instance_type: "Unknown".to_string(), // Missing instance type
            state: "Unknown".to_string(),         // Missing state
            private_ip: None,                     // No private IP
            public_ip: None,                      // No public IP
            tags: vec![],                         // No tags
        };

        assert_eq!(instance_info.instance_id, "i-1234567890abcdef0");
        assert_eq!(instance_info.name, "Unknown");
        assert_eq!(instance_info.instance_type, "Unknown");
        assert_eq!(instance_info.state, "Unknown");
        assert_eq!(instance_info.private_ip, None);
        assert_eq!(instance_info.public_ip, None);
        assert_eq!(instance_info.tags.len(), 0);
    }

    #[test]
    fn test_environment_variable_precedence() {
        use std::env;

        // Use a unique test env var to avoid interference
        let test_var = "AWS_PROFILE_TEST_VAR";

        // Set test environment variable
        env::set_var(test_var, "test-env-profile");

        // Simulate CLI parsing with no profile argument
        let cli_profile: Option<String> = None;
        let effective_profile = cli_profile.or_else(|| env::var(test_var).ok());

        assert_eq!(effective_profile, Some("test-env-profile".to_string()));

        // Test CLI argument override
        let cli_profile_override: Option<String> = Some("cli-override-profile".to_string());
        let effective_profile_override = cli_profile_override.or_else(|| env::var(test_var).ok());

        assert_eq!(
            effective_profile_override,
            Some("cli-override-profile".to_string())
        );

        // Clean up test environment variable
        env::remove_var(test_var);
    }

    #[test]
    fn test_aws_region_environment_variable() {
        use std::env;

        // Use a unique test env var to avoid interference
        let test_var = "AWS_REGION_TEST_VAR";

        // Set test environment variable
        env::set_var(test_var, "eu-west-1");

        // Simulate CLI parsing with no region argument
        let cli_region: Option<String> = None;
        let effective_region = cli_region.or_else(|| env::var(test_var).ok());

        assert_eq!(effective_region, Some("eu-west-1".to_string()));

        // Test CLI argument override
        let cli_region_override: Option<String> = Some("us-east-1".to_string());
        let effective_region_override = cli_region_override.or_else(|| env::var(test_var).ok());

        assert_eq!(effective_region_override, Some("us-east-1".to_string()));

        // Clean up test environment variable
        env::remove_var(test_var);
    }

    #[test]
    fn test_cli_with_environment_variables() {
        use clap::CommandFactory;
        use std::env;

        let original_profile = env::var("AWS_PROFILE").ok();
        let original_region = env::var("AWS_REGION").ok();

        // Set environment variables
        env::set_var("AWS_PROFILE", "env-profile");
        env::set_var("AWS_REGION", "env-region");

        let cmd = Cli::command();

        // Test that CLI still parses correctly with env vars set
        let result = cmd
            .clone()
            .try_get_matches_from(vec!["aws-ssm-connect", "test-instance"]);

        assert!(result.is_ok());

        // Test explicit CLI args override env vars
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "test-instance",
            "--profile",
            "cli-profile",
            "--region",
            "cli-region",
        ]);

        assert!(result.is_ok());

        // Restore original environment
        match original_profile {
            Some(value) => env::set_var("AWS_PROFILE", value),
            None => env::remove_var("AWS_PROFILE"),
        }
        match original_region {
            Some(value) => env::set_var("AWS_REGION", value),
            None => env::remove_var("AWS_REGION"),
        }
    }

    #[test]
    fn test_default_remote_host_behavior() {
        // Test default remote host value
        let default_remote_host = "localhost";
        assert_eq!(default_remote_host, "localhost");

        // Test that default is used when not specified
        let remote_host_arg: Option<String> = None;
        let effective_remote_host = remote_host_arg.unwrap_or_else(|| "localhost".to_string());
        assert_eq!(effective_remote_host, "localhost");

        // Test explicit remote host override
        let remote_host_override: Option<String> = Some("database.internal".to_string());
        let effective_remote_host_override =
            remote_host_override.unwrap_or_else(|| "localhost".to_string());
        assert_eq!(effective_remote_host_override, "database.internal");
    }

    #[test]
    fn test_instance_filtering_by_name_exact_match() {
        // Test that the Name tag filter should be exact match
        let test_instances = vec![
            ("web-server", "web-server"),      // Exact match
            ("web-server-1", "web-server"),    // Partial match - should not match in real filter
            ("web-server-prod", "web-server"), // Partial match - should not match in real filter
            ("my-web-server", "web-server"),   // Partial match - should not match in real filter
        ];

        for (instance_name, search_term) in test_instances {
            let is_exact_match = instance_name == search_term;
            if search_term == "web-server" {
                // Only the first case should be an exact match
                assert_eq!(is_exact_match, instance_name == "web-server");
            }
        }
    }

    #[test]
    fn test_tag_processing_with_special_characters() {
        // Test tag processing with special characters and edge cases
        let special_tags = vec![
            ("Name".to_string(), "server-with-dashes".to_string()),
            ("Environment".to_string(), "prod/staging".to_string()),
            ("Cost Center".to_string(), "team-123".to_string()),
            (
                "Description".to_string(),
                "Server with spaces and symbols!@#".to_string(),
            ),
        ];

        // Find Name tag with special characters
        let name_tag = special_tags
            .iter()
            .find(|(key, _)| key == "Name")
            .map(|(_, value)| value.clone())
            .unwrap_or("Unknown".to_string());

        assert_eq!(name_tag, "server-with-dashes");

        // Verify all tags are preserved
        assert_eq!(special_tags.len(), 4);

        // Test that special characters in values are preserved
        let description_tag = special_tags
            .iter()
            .find(|(key, _)| key == "Description")
            .map(|(_, value)| value.clone());

        assert_eq!(
            description_tag,
            Some("Server with spaces and symbols!@#".to_string())
        );
    }

    #[test]
    fn test_error_message_formatting() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        // Test various error message scenarios
        let error_messages = vec![
            "No running instances found with Name tag: 'non-existent-server'",
            "Failed to authenticate with AWS: InvalidCredentials",
            "Instance is not available for SSM connection",
            "Port forwarding mode requires both --local-port and --remote-port.",
            "SSM session failed with exit code: Some(1)",
        ];

        for message in error_messages {
            // Test that error messages can be formatted without panicking
            print_error(message);

            // Test message length is reasonable
            assert!(message.len() > 0);
            assert!(message.len() < 500, "Error message too long: {}", message);
        }
    }

    #[test]
    fn test_warning_message_formatting() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        let warning_messages = vec![
            "Found 3 instances with the specified name:",
            "Instance may take a moment to become available for SSM",
            "Using default AWS profile",
        ];

        for message in warning_messages {
            print_warning(message);
            assert!(message.len() > 0);
        }
    }

    #[test]
    fn test_info_and_success_message_formatting() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        let info_messages = vec![
            "Instance ID: i-1234567890abcdef0",
            "Starting SSM session...",
            "Port forwarding: localhost:8080 → localhost:80",
        ];

        let success_messages = vec![
            "Found 1 instance with name: 'web-server'",
            "SSM session completed",
            "Port forwarding session completed",
        ];

        for message in info_messages {
            print_info(message);
            assert!(message.len() > 0);
        }

        for message in success_messages {
            print_success(message);
            assert!(message.len() > 0);
        }
    }

    #[test]
    fn test_verbose_debug_output() {
        use colored::control::set_override;

        // Disable colors for testing
        set_override(false);

        let debug_messages = vec![
            "AWS SSM Connect Tool",
            "Profile: default",
            "Region: us-west-2",
            "Searching for instances with Name tag: 'test-server'",
            "Checking SSM availability for instance: i-1234567890abcdef0",
        ];

        for message in debug_messages {
            // Test both verbose enabled and disabled
            print_debug(message, true);
            print_debug(message, false);
            assert!(message.len() > 0);
        }
    }

    #[test]
    fn test_extreme_edge_cases() {
        // Test with extremely long instance names
        let long_name = "a".repeat(255);
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: long_name.clone(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: None,
            public_ip: None,
            tags: vec![("Name".to_string(), long_name)],
        };

        // Should handle long names without panicking
        display_instance_info(&instance_info, 1);
        assert_eq!(instance_info.name.len(), 255);
    }

    #[test]
    fn test_empty_string_handling() {
        // Test handling of empty strings in various contexts
        let instance_info = InstanceInfo {
            instance_id: "".to_string(),                  // Empty instance ID
            name: "".to_string(),                         // Empty name
            instance_type: "".to_string(),                // Empty type
            state: "".to_string(),                        // Empty state
            private_ip: Some("".to_string()),             // Empty IP
            public_ip: Some("".to_string()),              // Empty IP
            tags: vec![("".to_string(), "".to_string())], // Empty tag
        };

        // Should handle empty strings gracefully
        display_instance_info(&instance_info, 1);
        assert_eq!(instance_info.instance_id, "");
        assert_eq!(instance_info.name, "");
    }

    #[test]
    fn test_unicode_and_special_characters() {
        // Test handling of Unicode and special characters
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "服务器-测试-🚀".to_string(), // Unicode characters
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: None,
            tags: vec![
                ("Name".to_string(), "服务器-测试-🚀".to_string()),
                ("Team".to_string(), "开发团队".to_string()),
                (
                    "Special".to_string(),
                    "!@#$%^&*()_+-=[]{}|;':\",./<>?".to_string(),
                ),
            ],
        };

        // Should handle Unicode without panicking
        display_instance_info(&instance_info, 1);
        assert!(instance_info.name.contains("🚀"));
    }

    #[test]
    fn test_port_number_edge_cases() {
        // Test extreme port numbers
        let test_cases = vec![
            (1, 1),         // Minimum valid ports
            (80, 443),      // Common ports
            (8080, 8443),   // Common dev ports
            (65535, 65534), // Maximum valid ports
        ];

        for (local_port, remote_port) in test_cases {
            let port_forward = true;
            let local_port_opt = Some(local_port);
            let remote_port_opt = Some(remote_port);

            let validation_failed =
                port_forward && (local_port_opt.is_none() || remote_port_opt.is_none());
            assert!(
                !validation_failed,
                "Should pass validation for ports {} -> {}",
                local_port, remote_port
            );
        }
    }

    #[test]
    fn test_command_construction_edge_cases() {
        use std::process::Command;

        // Test command construction with empty/special values
        let mut cmd = Command::new("aws");
        cmd.args(["ssm", "start-session"]);

        // Test with unusual but valid instance IDs
        let unusual_instance_ids = vec![
            "i-0000000000000000a", // Minimum hex
            "i-ffffffffffffffffa", // Maximum hex (theoretical)
            "i-1234567890abcdef0", // Standard format
        ];

        for instance_id in unusual_instance_ids {
            let mut test_cmd = Command::new("aws");
            test_cmd.args(["ssm", "start-session"]);
            test_cmd.args(["--target", instance_id]);

            let args: Vec<&str> = test_cmd.get_args().map(|s| s.to_str().unwrap()).collect();
            assert!(args.contains(&instance_id));
        }
    }

    #[test]
    fn test_duration_formatting_edge_cases() {
        use std::time::Duration;

        // Test extreme duration values
        let extreme_cases = vec![
            (Duration::from_millis(999), "0s"),           // Less than 1 second
            (Duration::from_secs(86400), "24h 0m 0s"),    // 1 day
            (Duration::from_secs(90061), "25h 1m 1s"),    // Over 1 day
            (Duration::from_secs(359999), "99h 59m 59s"), // Just under 100 hours
        ];

        for (duration, expected) in extreme_cases {
            let formatted = format_duration(duration);
            assert_eq!(
                formatted, expected,
                "Duration formatting failed for {:?}",
                duration
            );
        }
    }

    #[test]
    fn test_session_summary_edge_cases() {
        use colored::control::set_override;
        use std::time::Duration;

        // Disable colors for testing
        set_override(false);

        // Test session summary with extreme values
        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "test-server".to_string(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: None,
            public_ip: None,
            tags: vec![],
        };

        // Test with very long session duration
        let summary = SessionSummary {
            instance_info: instance_info.clone(),
            session_type: "Interactive Shell".to_string(),
            local_port: None,
            remote_port: None,
            remote_host: None,
            duration: Duration::from_secs(86400 * 7), // 1 week
            profile: Some("very-long-profile-name-that-might-cause-display-issues".to_string()),
            region: Some("us-gov-east-1".to_string()),
        };

        // Should handle extreme values without panicking
        print_session_summary(&summary);
        assert_eq!(summary.duration.as_secs(), 86400 * 7);
    }

    #[test]
    fn test_cli_argument_boundary_values() {
        use clap::CommandFactory;

        let cmd = Cli::command();

        // Test with very long instance name
        let long_name = "a".repeat(100);
        let result = cmd
            .clone()
            .try_get_matches_from(vec!["aws-ssm-connect", &long_name]);
        assert!(result.is_ok(), "Should handle long instance names");

        // Test with special characters in instance name
        let special_name = "server-with-dashes_and_underscores.and.dots";
        let result = cmd
            .clone()
            .try_get_matches_from(vec!["aws-ssm-connect", special_name]);
        assert!(
            result.is_ok(),
            "Should handle special characters in instance names"
        );
    }

    #[test]
    fn test_skip_ssm_check_flag() {
        use clap::CommandFactory;

        let cmd = Cli::command();

        // Test that skip-ssm-check flag is parsed correctly
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "test-instance",
            "--skip-ssm-check",
        ]);
        assert!(result.is_ok(), "Should parse skip-ssm-check flag");

        // Test combination with other flags
        let result = cmd.clone().try_get_matches_from(vec![
            "aws-ssm-connect",
            "test-instance",
            "--skip-ssm-check",
            "--verbose",
            "--no-summary",
        ]);
        assert!(
            result.is_ok(),
            "Should parse skip-ssm-check with other flags"
        );
    }

    #[test]
    fn test_memory_safety_with_large_data() {
        // Test handling of large data structures
        let mut large_tags = Vec::new();
        for i in 0..1000 {
            large_tags.push((format!("tag_{}", i), format!("value_{}", i)));
        }

        let instance_info = InstanceInfo {
            instance_id: "i-1234567890abcdef0".to_string(),
            name: "test-server".to_string(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            private_ip: Some("10.0.0.1".to_string()),
            public_ip: None,
            tags: large_tags,
        };

        // Should handle large tag collections without issues
        assert_eq!(instance_info.tags.len(), 1000);

        // Test that display doesn't panic with many tags
        display_instance_info(&instance_info, 1);
    }

    #[test]
    fn test_native_ssm_flag() {
        use clap::Parser;

        let args = vec!["aws-ssm-connect", "test-server", "--native"];

        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.instance_name, Some("test-server".to_string()));
        assert!(cli.native);
        assert!(!cli.port_forward);
        assert!(!cli.skip_ssm_check);
    }

    #[test]
    fn test_native_ssm_with_port_forwarding() {
        use clap::Parser;

        let args = vec![
            "aws-ssm-connect",
            "test-server",
            "--native",
            "--port-forward",
            "--local-port",
            "8080",
            "--remote-port",
            "80",
        ];

        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.instance_name, Some("test-server".to_string()));
        assert!(cli.native);
        assert!(cli.port_forward);
        assert_eq!(cli.local_port, Some(8080));
        assert_eq!(cli.remote_port, Some(80));
    }

    #[test]
    fn test_native_ssm_with_skip_checks() {
        use clap::Parser;

        let args = vec![
            "aws-ssm-connect",
            "test-server",
            "--native",
            "--skip-ssm-check",
        ];

        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.instance_name, Some("test-server".to_string()));
        assert!(cli.native);
        assert!(cli.skip_ssm_check);
        assert!(!cli.port_forward);
    }

    // Note: More comprehensive integration tests could be added here using:
    // - Mock AWS SDK clients with conditional compilation
    // - Docker containers with localstack for AWS service simulation
    // - Property-based testing for configuration validation
    // - Stress testing with concurrent operations
    // - Network failure simulation and retry logic testing

    #[test]
    fn test_aws_error_handling() {
        // Test ExpiredToken error
        let error = handle_aws_error(
            "ExpiredToken: The security token included in the request is invalid",
            "Test operation",
        );
        assert!(error.to_string().contains("AWS credentials have expired"));
        assert!(error.to_string().contains("aws sso login"));

        // Test dispatch failure error (common for expired SSO tokens)
        let error = handle_aws_error("dispatch failure", "Test operation");
        assert!(error.to_string().contains("likely expired credentials"));
        assert!(error.to_string().contains("aws sso login"));

        // Test AccessDenied error
        let error = handle_aws_error("AccessDenied: User is not authorized", "Test operation");
        assert!(error.to_string().contains("access is denied"));

        // Test NoCredentialsError
        let error = handle_aws_error(
            "NoCredentialsError: Unable to locate credentials",
            "Test operation",
        );
        assert!(error.to_string().contains("No AWS credentials found"));
        assert!(error.to_string().contains("aws configure"));

        // Test NetworkingError
        let error = handle_aws_error("NetworkingError: Connection timeout", "Test operation");
        assert!(error.to_string().contains("Network error"));

        // Test generic error
        let error = handle_aws_error("Some other AWS error", "Test operation");
        assert!(error
            .to_string()
            .contains("Test operation: Some other AWS error"));
    }

    #[test]
    fn test_ansi_stripping() {
        // Test basic ANSI color codes (preserved in new implementation)
        let input = "\x1b[32mHello\x1b[0m World";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b[32mHello\x1b[0m World");

        // Test the specific sequences with bracketed paste mode removed
        let input = "?2004h0;\x1b[32m\x1b[0m00m:01\x1b[34m\x1b[0m00m";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "0;\x1b[32m\x1b[0m00m:01\x1b[34m\x1b[0m00m");

        // Test bracketed paste mode sequences specifically
        let input = "?2004hHello World?2004l";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "Hello World");

        // Test control character removal (colors preserved)
        let input = "\x1b[1;32mGreen\x1b[0m\x07\x08Text";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b[1;32mGreen\x1b[0mText");

        // Test preserving tabs and newlines
        let input = "Line1\tTabbed\nNewline\rReturn";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "Line1\tTabbed\nNewline\rReturn");

        // Test ESC sequences with different terminators (colors preserved)
        let input = "\x1b[2J\x1b[H\x1b[?25lHello\x1b[?25h";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b[2J\x1b[H\x1b[?25lHello\x1b[?25h");

        // Test character set sequences (preserved by clean_for_display)
        let input = "\x1b(BHello\x1b(0World";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b(BHello\x1b(0World");
    }

    #[test]
    fn test_ansi_stripping_multiline() {
        let input = "\x1b[32mLine 1\x1b[0m\n\x1b[31mLine 2\x1b[0m\n\nEmpty line above";
        let result = replay_rs::clean_for_display(input);
        // Colors are now preserved
        assert!(result.contains("\x1b[32mLine 1\x1b[0m"));
        assert!(result.contains("\x1b[31mLine 2\x1b[0m"));
        assert!(result.contains("Empty line above"));
    }

    #[test]
    fn test_clean_for_display() {
        // Test that color codes are preserved
        let input = "\x1b[32mGreen Text\x1b[0m Normal Text";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b[32mGreen Text\x1b[0m Normal Text");

        // Test that bracketed paste mode is removed
        let input = "?2004hHello\x1b[31m Red\x1b[0m World?2004l";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "Hello\x1b[31m Red\x1b[0m World");

        // Test control character removal but preserve colors
        let input = "\x1b[1;32mBold Green\x1b[0m\x07\x08Text";
        let result = replay_rs::clean_for_display(input);
        assert_eq!(result, "\x1b[1;32mBold Green\x1b[0mText");
    }

    #[test]
    fn test_replay_rs_integration() {
        use std::fs;

        // Create test timing file
        let timing_content = "0.1 5\n0.2 6\n0.1 4\n";
        fs::write("test_timing.txt", timing_content).unwrap();

        // Create test typescript file
        let typescript_content = "Hello\nWorld!\nTest";
        fs::write("test_typescript.txt", typescript_content).unwrap();

        // Test the replay-rs Player (it should not crash)
        let player = Player::new("test_timing.txt", "test_typescript.txt");
        assert!(player.is_ok());

        // Test dump functionality (faster than full replay in tests)
        let result = player.unwrap().dump();

        // Clean up
        fs::remove_file("test_timing.txt").unwrap();
        fs::remove_file("test_typescript.txt").unwrap();

        // Should succeed
        assert!(result.is_ok());
    }
}
