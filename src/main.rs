//! `webmcp` command-line interface.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use tracing_subscriber::EnvFilter;

use webmcp_daemon::config::{self, Config, ServerEntry};
use webmcp_daemon::connect::{self, ConnectOptions};
use webmcp_daemon::device_auth::{self, DeviceAuthError, PollTiming, StartRequest};
use webmcp_daemon::discover::{self, Discovered, Roots};
use webmcp_daemon::lock::{InstanceLock, LockError};
use webmcp_daemon::output::{self, ServiceOutcome, UpEvent, UpReport};
use webmcp_daemon::pair::{self, PairError, PairRequest};
use webmcp_daemon::proto::SessionMode;
use webmcp_daemon::{keys, platform, service, Error};

const DEFAULT_BASE_URL: &str = "https://webmcp.fast";

#[derive(Parser)]
#[command(
    name = "webmcp",
    version,
    about = "Expose local MCP servers through webmcp.fast",
    long_about = None
)]
struct Cli {
    /// Machine-readable output for up, discover, status, servers, attach,
    /// detach and service status: one JSON object on stdout (logs stay on
    /// stderr). `up` prints one extra `approval_required` line first when it
    /// has to pair. Other commands emit JSON only on error. Exit codes: 0 ok,
    /// 1 error, 2 approval declined, 3 approval expired
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set this machine up in one go: pair, attach servers, run in the
    /// background. Safe to run again at any point
    Up(UpArgs),
    /// List MCP servers other tools on this machine are configured with
    Discover,
    /// Pair this machine with your webmcp.fast account
    Login(LoginArgs),
    /// Hold the relay connection open (Ctrl-C to stop)
    Connect(ConnectArgs),
    /// Show the pairing state of this machine
    Status,
    /// Attach a local MCP server under an alias
    Attach(AttachArgs),
    /// Detach a server by alias
    Detach { alias: String },
    /// List attached servers
    Servers,
    /// Keep the daemon running in the background (macOS launchd, Linux systemd)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Start `webmcp connect` at login and restart it if it stops
    Install,
    /// Stop the background service and remove it (pairing and servers are kept)
    Uninstall,
    /// Show whether the background service is installed and running
    Status,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
    webmcp up                                   # interactive: asks before attaching or installing\n  \
    webmcp up --json --attach github --service  # for an agent: no prompts, two JSON lines at most")]
struct UpArgs {
    /// Device name (1-32 chars, [a-z0-9-]); defaults to the hostname
    #[arg(long)]
    name: Option<String>,
    /// API base URL [default: https://webmcp.fast]
    #[arg(long)]
    base_url: Option<String>,
    /// Do not try to open the approval link in the default browser
    #[arg(long)]
    no_browser: bool,
    /// Pair again even if this machine is already paired (after a revoke);
    /// attached servers are kept
    #[arg(long)]
    force: bool,
    /// Attach this discovered server, by name or alias as `webmcp discover`
    /// shows it (repeatable). Its env variables are copied into the webmcp config
    #[arg(long, value_name = "NAME", conflicts_with = "no_attach")]
    attach: Vec<String>,
    /// Do not offer discovered servers
    #[arg(long)]
    no_attach: bool,
    /// Install the background service without asking (macOS, Linux)
    #[arg(long)]
    service: bool,
}

#[derive(Args)]
struct LoginArgs {
    /// Pairing code from the dashboard, e.g. ABCD-EFGH
    #[arg(long)]
    code: String,
    /// Device name (1-32 chars, [a-z0-9-]); defaults to the hostname
    #[arg(long)]
    name: Option<String>,
    /// API base URL
    #[arg(long, default_value = DEFAULT_BASE_URL)]
    base_url: String,
    /// Re-pair even if this machine already has a config
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ConnectArgs {
    /// Exit after the first welcome and one ping/pong round
    #[arg(long)]
    once: bool,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
    webmcp attach fs -- npx -y @modelcontextprotocol/server-filesystem /tmp\n  \
    webmcp attach fs --env DEBUG=1 --cwd ~/work --stdio \"npx -y @scope/server\"\n  \
    webmcp attach gnosys --http http://localhost:8765/mcp --mode shared")]
struct AttachArgs {
    /// Alias, unique per device: ^[a-z0-9][a-z0-9-]{0,31}$
    alias: String,
    /// Command line of a stdio MCP server as one string, e.g. "npx -y @scope/server"
    #[arg(long, value_name = "COMMAND", conflicts_with_all = ["http", "command"])]
    stdio: Option<String>,
    /// URL of a local HTTP MCP server (localhost, 127.0.0.1 or ::1 only)
    #[arg(long, value_name = "URL", conflicts_with = "command")]
    http: Option<String>,
    /// Session model for this server
    #[arg(long, value_enum, default_value_t = SessionMode::PerSession)]
    mode: SessionMode,
    /// Environment variable for a stdio server (repeatable)
    #[arg(long = "env", value_name = "KEY=VAL", conflicts_with = "http")]
    env: Vec<String>,
    /// Working directory for a stdio server
    #[arg(long, value_name = "DIR", conflicts_with = "http")]
    cwd: Option<PathBuf>,
    /// Concurrent sessions allowed on this server [default: 4]
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: Option<u32>,
    /// Command and arguments of a stdio MCP server, after `--`
    #[arg(last = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let message = format!("{e:#}");
            if json {
                println!(
                    "{}",
                    output::line(&output::ErrorReport::new("error", &message))
                );
            }
            eprintln!("error: {message}");
            1
        }
    };
    std::process::exit(code);
}

/// Runs one command and returns the process exit code. Only `up` uses
/// anything but 0: it reports its own failures (2 declined, 3 expired).
fn run(cli: Cli) -> Result<i32> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let json = cli.json;
    let dir = config::config_dir()?;
    match cli.command {
        Command::Up(args) => return runtime()?.block_on(up(dir, args, json)),
        Command::Discover => discover_cmd(json)?,
        Command::Login(args) => runtime()?.block_on(login(dir, args))?,
        Command::Connect(args) => runtime()?.block_on(connect_cmd(dir, args))?,
        Command::Status => status(dir, json)?,
        Command::Attach(args) => attach(dir, args, json)?,
        Command::Detach { alias } => detach(dir, &alias, json)?,
        Command::Servers => servers(dir, json)?,
        Command::Service { action } => service_cmd(action, json)?,
    }
    Ok(0)
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start async runtime")
}

fn load_config(dir: &Path) -> Result<Config> {
    Config::load_from(dir).with_context(|| format!("reading {}", Config::path_in(dir).display()))
}

/// Device name and hardware id for a pairing request, shared by `login` and
/// `up`. `existing` is the config being replaced, if any.
fn identity(name: Option<String>, existing: Option<&Config>) -> Result<(String, String)> {
    let device_name = match name {
        Some(n) => {
            if !config::is_valid_device_name(&n) {
                bail!(
                    "device name `{n}`: 1-32 of a-z, 0-9 and -, starting and ending with a letter or digit"
                );
            }
            n
        }
        None => platform::default_device_name(),
    };
    let hardware_id = platform::hardware_id().unwrap_or_else(|| {
        // Reuse a previously generated id so re-pairing stays stable.
        if let Some(cfg) = existing {
            tracing::warn!("no machine id available; reusing the stored random hardware id");
            cfg.hardware_id.clone()
        } else {
            tracing::warn!("no machine id available; generating a random hardware id");
            platform::random_hardware_id()
        }
    });
    Ok((device_name, hardware_id))
}

async fn login(dir: PathBuf, args: LoginArgs) -> Result<()> {
    let existing = Config::try_load_from(&dir)?;
    if let Some(cfg) = &existing {
        if !args.force {
            bail!(
                "this machine is already paired as {}/{} (device {}); pass --force to pair again",
                cfg.handle,
                cfg.device_name,
                cfg.device_id
            );
        }
        tracing::warn!("re-pairing; the previous device identity will be overwritten");
    }

    let (device_name, hardware_id) = identity(args.name, existing.as_ref())?;

    let key = keys::generate();
    let req = PairRequest {
        code: pair::normalize_code(&args.code),
        device_name: device_name.clone(),
        public_key: keys::public_key_b64(&key),
        hardware_id: hardware_id.clone(),
        daemon_version: platform::VERSION.to_string(),
        platform: platform::platform(),
    };
    if req.code.len() != 8 {
        bail!(
            "pairing code must be 8 characters (like ABCD-EFGH), got `{}`",
            args.code
        );
    }

    tracing::info!(device_name, base_url = %args.base_url, "pairing");
    let resp = match pair::pair(&args.base_url, &req).await {
        Ok(r) => r,
        Err(e @ PairError::CodeNotFound) => bail!(
            "{e}\nCreate a new code at {}/app/devices and retry.",
            args.base_url.trim_end_matches('/')
        ),
        Err(e) => return Err(e.into()),
    };

    let servers = existing.map(|c| c.servers).unwrap_or_default();
    let cfg = pair::persist(&dir, &key, resp, device_name, hardware_id, servers)?;

    println!(
        "Paired as {}/{} (device id {}).",
        cfg.handle, cfg.device_name, cfg.device_id
    );
    println!("Config: {}", Config::path_in(&dir).display());
    println!("Next: run `webmcp connect` to bring this device online.");
    Ok(())
}

/// Progress lines of `up`: stdout for a person, stderr in JSON mode, where
/// stdout belongs to the JSON lines alone.
fn say(json: bool, text: impl AsRef<str>) {
    if json {
        eprintln!("{}", text.as_ref());
    } else {
        println!("{}", text.as_ref());
    }
}

/// Ask on the terminal; any read failure is an empty answer.
fn prompt(question: &str) -> String {
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().to_string()
}

/// Best effort: a headless box or a missing `xdg-open` is not an error, the
/// link is printed either way.
fn open_in_browser(link: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        "xdg-open"
    } else {
        return;
    };
    let spawned = std::process::Command::new(opener)
        .arg(link)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Err(e) = spawned {
        tracing::debug!(error = %e, opener, "could not open the browser");
    }
}

/// True while some `webmcp connect` (service or terminal) holds the instance
/// lock for this config directory.
fn daemon_running(dir: &Path) -> bool {
    matches!(InstanceLock::acquire(dir), Err(LockError::Held { .. }))
}

/// What `up` has achieved so far; the final report is built from it whether
/// the run succeeds or fails half way.
struct UpState {
    cfg: Option<Config>,
    /// `(alias, env names)` of the servers attached by this run.
    carried: Vec<(String, Vec<String>)>,
    service: ServiceOutcome,
}

/// `webmcp up`: pair, offer servers, offer the service, report. Each step is
/// skipped when already done, so running it again is always safe.
async fn up(dir: PathBuf, args: UpArgs, json: bool) -> Result<i32> {
    // An agent on a pipe must never be left waiting on a prompt.
    let interactive = !json && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut state = UpState {
        cfg: None,
        carried: Vec::new(),
        service: if service::supported() {
            ServiceOutcome::Skipped
        } else {
            ServiceOutcome::Unsupported
        },
    };
    let outcome = up_steps(&dir, &args, json, interactive, &mut state).await;

    let servers = state
        .cfg
        .as_ref()
        .map(|cfg| UpReport::servers_of(cfg, &state.carried))
        .unwrap_or_default();
    let (event, exit, code, message, next) = match &outcome {
        Ok(()) => {
            let online = state.service == ServiceOutcome::Installed || daemon_running(&dir);
            let next = if servers.is_empty() {
                "No servers attached yet. Run `webmcp discover` to see what this machine already has, then `webmcp up --attach <name>` (or `webmcp attach <alias> -- <command>`).".to_string()
            } else if online {
                output::NEXT_CONNECTOR.to_string()
            } else {
                format!(
                    "Run `webmcp connect` (or `webmcp up --service`) to bring this device online. Then: {}",
                    output::NEXT_CONNECTOR
                )
            };
            (UpEvent::Ready, 0, None, None, next)
        }
        Err(e) => {
            let auth = e.downcast_ref::<DeviceAuthError>();
            (
                UpEvent::Error,
                auth.map_or(1, DeviceAuthError::exit_code),
                Some(auth.map_or("error", DeviceAuthError::code).to_string()),
                Some(format!("{e:#}")),
                "Fix the problem above and run `webmcp up` again; finished steps are kept."
                    .to_string(),
            )
        }
    };

    if json {
        let report = UpReport {
            event,
            handle: state.cfg.as_ref().map(|c| c.handle.clone()),
            device: state.cfg.as_ref().map(|c| c.device_name.clone()),
            servers,
            service: state.service,
            next,
            code,
            message: message.clone(),
        };
        println!("{}", output::line(&report));
    } else if outcome.is_ok() {
        println!();
        for s in &servers {
            println!("  {:<12} {}", s.alias, s.url.as_deref().unwrap_or("?"));
        }
        println!("{next}");
    }
    if let Some(message) = message {
        eprintln!("error: {message}");
    }
    Ok(exit)
}

async fn up_steps(
    dir: &Path,
    args: &UpArgs,
    json: bool,
    interactive: bool,
    state: &mut UpState,
) -> Result<()> {
    // 1. Pair, unless this machine already has both halves of an identity.
    let existing = Config::try_load_from(dir)?;
    let has_key = match keys::load(dir) {
        Ok(_) => true,
        Err(Error::NotPaired) => false,
        Err(e) => return Err(e.into()),
    };
    let cfg = match existing {
        Some(cfg) if has_key && !args.force => {
            say(
                json,
                format!("Already paired as {}/{}.", cfg.handle, cfg.device_name),
            );
            cfg
        }
        existing => up_pair(dir, args, json, existing).await?,
    };
    state.cfg = Some(cfg);
    let cfg = state.cfg.as_mut().expect("just set");

    // 2. Offer what other tools here already use. Nothing is attached without
    // an explicit flag or an interactive choice.
    if !args.no_attach {
        let picked = up_pick(cfg, args, json, interactive)?;
        for d in picked {
            if cfg.servers.iter().any(|s| s.alias == d.alias) {
                say(json, format!("{}: already attached.", d.alias));
                continue;
            }
            let entry = d.to_entry(&d.alias, SessionMode::default())?;
            let names: Vec<String> = d.env_names().iter().map(|n| n.to_string()).collect();
            cfg.attach(entry)?;
            cfg.save_to(dir)?;
            say(json, format!("Attached {}: {}", d.alias, d.target()));
            if !names.is_empty() {
                // Names only. The values are API keys.
                say(
                    json,
                    format!(
                        "  copied into the webmcp config so the server gets them: {} (values not shown; stored in {})",
                        names.join(", "),
                        Config::path_in(dir).display()
                    ),
                );
            }
            state.carried.push((d.alias.clone(), names));
        }
    }

    // 3. Background service.
    if service::supported() {
        let home = home_dir()?;
        let st = service::status(&home)?;
        if st.installed && st.pid.is_some() {
            say(json, "Background service: already running.");
            state.service = ServiceOutcome::Installed;
        } else if args.service
            || (interactive
                && matches!(
                    prompt("Keep this device online in the background (starts at login)? [Y/n] ")
                        .to_ascii_lowercase()
                        .as_str(),
                    "" | "y" | "yes"
                ))
        {
            let (_, log) = install_service(home)?;
            say(
                json,
                format!("Background service installed (log: {}).", log.display()),
            );
            if let Some(hint) = service::post_install_hint() {
                say(json, hint);
            }
            state.service = ServiceOutcome::Installed;
        } else {
            say(
                json,
                "Background service: skipped. `webmcp up --service` installs it; `webmcp connect` runs in the foreground.",
            );
        }
    } else {
        say(
            json,
            "Background service: not available on this platform yet. Run `webmcp connect` under your own supervisor.",
        );
    }
    Ok(())
}

/// Step 1 of `up`: the §1a device authorization flow. `existing` is the
/// config being replaced (`--force`, or its key went missing); its servers
/// survive the re-pair.
async fn up_pair(
    dir: &Path,
    args: &UpArgs,
    json: bool,
    existing: Option<Config>,
) -> Result<Config> {
    if existing.is_some() {
        tracing::warn!(
            "pairing again; the previous device identity is replaced, attached servers are kept"
        );
    }
    let base_url = args.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
    let (device_name, hardware_id) = identity(args.name.clone(), existing.as_ref())?;
    // The key exists before `start`, so the approval binds to it.
    let key: SigningKey = keys::generate();
    let req = StartRequest {
        device_name: device_name.clone(),
        public_key: keys::public_key_b64(&key),
        hardware_id: hardware_id.clone(),
        daemon_version: platform::VERSION.to_string(),
        platform: platform::platform(),
    };
    tracing::info!(device_name, %base_url, "starting device authorization");
    let started = device_auth::start(base_url, &req).await?;

    if json {
        println!(
            "{}",
            output::line(&output::ApprovalRequired::new(
                &started.verification_uri_complete,
                &started.user_code,
                started.expires_in,
            ))
        );
    }
    say(json, "To pair this machine, open this link and approve it:");
    say(
        json,
        format!("\n    {}\n", started.verification_uri_complete),
    );
    say(
        json,
        format!(
            "On another device: {} and enter {}. Waiting up to {} min…",
            started.verification_uri,
            started.user_code,
            started.expires_in.div_ceil(60)
        ),
    );
    if !args.no_browser {
        open_in_browser(&started.verification_uri_complete);
    }

    let resp = device_auth::wait(base_url, &started, &device_name, PollTiming::default()).await?;
    let servers = existing.map(|c| c.servers).unwrap_or_default();
    let cfg = pair::persist(dir, &key, resp, device_name, hardware_id, servers)?;
    say(
        json,
        format!(
            "Paired as {}/{} (device id {}).",
            cfg.handle, cfg.device_name, cfg.device_id
        ),
    );
    Ok(cfg)
}

/// Step 2 of `up`: which discovered servers to attach. `--attach` names win;
/// otherwise a person at a terminal is asked, and only when nothing is
/// attached yet.
fn up_pick(cfg: &Config, args: &UpArgs, json: bool, interactive: bool) -> Result<Vec<Discovered>> {
    if args.attach.is_empty() && !cfg.servers.is_empty() {
        return Ok(Vec::new());
    }
    let Some(roots) = Roots::from_env() else {
        if !args.attach.is_empty() {
            bail!("--attach needs HOME and a current directory to look for servers in");
        }
        return Ok(Vec::new());
    };
    let found = discover::discover(&roots);
    if !args.attach.is_empty() {
        let mut picked: Vec<Discovered> = Vec::new();
        for wanted in &args.attach {
            let d = discover::resolve(&found, wanted)?;
            if !picked.iter().any(|p| p.alias == d.alias) {
                picked.push(d.clone());
            }
        }
        return Ok(picked);
    }

    let attachable: Vec<&Discovered> = found.iter().filter(|d| d.attachable()).collect();
    if attachable.is_empty() {
        say(json, "No local MCP servers found in other tools' configs.");
        return Ok(Vec::new());
    }
    if !interactive {
        say(
            json,
            format!(
                "{} local MCP server(s) found but none attached: see `webmcp discover`, then `webmcp up --attach <name>`.",
                attachable.len()
            ),
        );
        return Ok(Vec::new());
    }
    println!("MCP servers already configured on this machine:");
    for (i, d) in attachable.iter().enumerate() {
        println!("  {:>2}. {:<20} {}", i + 1, d.alias, describe(d));
    }
    loop {
        let answer = prompt("Attach which? (numbers like 1,3; `all`; Enter for none) ");
        match discover::parse_selection(&answer, attachable.len()) {
            Ok(picked) => return Ok(picked.into_iter().map(|i| attachable[i].clone()).collect()),
            Err(e) => println!("{e}"),
        }
    }
}

/// One line about a discovered server: target, env NAMES, where it came from.
fn describe(d: &Discovered) -> String {
    let mut clients: Vec<&str> = d.sources.iter().map(|s| s.client).collect();
    clients.dedup();
    let env = d.env_names();
    let env = if env.is_empty() {
        String::new()
    } else {
        format!("  env: {}", env.join(", "))
    };
    format!("{}{env}  [{}]", d.target(), clients.join(", "))
}

fn discover_cmd(json: bool) -> Result<()> {
    let roots = Roots::from_env().context("HOME is not set or the current directory is gone")?;
    let found = discover::discover(&roots);
    if json {
        println!("{}", output::line(&output::DiscoverReport::new(&found)));
        return Ok(());
    }
    if found.is_empty() {
        println!("No MCP servers found in Claude Code, Claude Desktop, Cursor, Codex or VS Code configs.");
        return Ok(());
    }
    let width = found
        .iter()
        .map(|d| d.alias.len())
        .max()
        .unwrap_or(5)
        .max(5);
    println!("{:<width$}  {:<5}  DEFINITION", "ALIAS", "KIND");
    for d in &found {
        let note = d
            .not_attachable()
            .map(|why| format!("  ({why})"))
            .unwrap_or_default();
        println!(
            "{:<width$}  {:<5}  {}{note}",
            d.alias,
            d.kind(),
            describe(d)
        );
    }
    println!("\nAttach with `webmcp up --attach <alias>`. Env values are never shown; attaching copies them into the webmcp config.");
    Ok(())
}

async fn connect_cmd(dir: PathBuf, args: ConnectArgs) -> Result<()> {
    let cfg = load_config(&dir)?;
    let key = keys::load(&dir)?;
    // One daemon per device: a second one would only trade the gateway's
    // single socket back and forth with the first. Held until we return.
    let _lock = InstanceLock::acquire(&dir)?;
    let mut opts = ConnectOptions::new(cfg.relay_url.clone(), cfg.device_id.clone(), key);
    opts.serve(&cfg.servers);
    opts.once = args.once;
    // `attach` and `detach` edit this file while we run; follow it.
    opts.config_path = Some(Config::path_in(&dir));
    for s in opts.servers.iter().filter(|s| s.error.is_some()) {
        tracing::warn!(server = %s.alias, "{}", s.error.as_deref().unwrap_or(""));
    }
    tracing::info!(
        handle = %cfg.handle,
        device = %cfg.device_name,
        relay = %cfg.relay_url,
        servers = opts.servers.len(),
        "connecting"
    );

    // launchd stops a service with SIGTERM; leave as cleanly as on Ctrl-C so
    // per-session children are killed rather than orphaned.
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("could not listen for SIGTERM")?;
    #[cfg(unix)]
    let terminated = term.recv();
    #[cfg(not(unix))]
    let terminated = std::future::pending::<Option<()>>();
    let outcome = tokio::select! {
        r = connect::run(&opts) => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; disconnecting");
            return Ok(());
        }
        _ = terminated => {
            tracing::info!("terminated; disconnecting");
            return Ok(());
        }
    };
    match outcome {
        Ok(w) => {
            println!(
                "Connected as {}/{} (server time {}); ping/pong ok.",
                w.handle, w.device, w.server_time
            );
            Ok(())
        }
        // Under the background service a clean exit means "do not restart me":
        // re-pairing needs the user, looping on a revoked key helps nobody,
        // and coming back after `Replaced` would restart the fight.
        Err(e) if e.is_fatal() && std::env::var_os(service::SERVICE_ENV).is_some() => {
            tracing::error!(error = %e, "stopping the background service");
            Ok(())
        }
        Err(e) => Err(anyhow::Error::new(e)),
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// Install (or refresh) the background service; returns the definition
/// (plist or unit) and log paths.
fn install_service(home: PathBuf) -> Result<(PathBuf, PathBuf)> {
    // Fail early, in the terminal, rather than silently in a log file.
    let dir = config::config_dir()?;
    load_config(&dir)?;
    let spec = service::ServiceSpec {
        program: std::env::current_exe().context("could not locate the webmcp binary")?,
        path_env: std::env::var("PATH").unwrap_or_default(),
        config_dir: std::env::var_os(config::CONFIG_DIR_ENV).map(PathBuf::from),
        log_file: service::log_path(&home),
        home,
    };
    let definition = service::install(&spec)?;
    if let Some(manager) = service::node_version_manager(&spec.program) {
        eprintln!(
            "note: this webmcp binary lives inside {manager}'s per-version Node directory. \
             After switching Node versions, reinstall webmcp and run `webmcp service install` again."
        );
    }
    Ok((definition, spec.log_file))
}

fn service_cmd(action: ServiceAction, json: bool) -> Result<()> {
    let home = home_dir()?;
    match action {
        ServiceAction::Install => {
            let (definition, log) = install_service(home)?;
            println!("Installed and started the background service.");
            println!("It starts at login and restarts if it stops. `webmcp connect` is no longer needed.");
            println!("definition: {}", definition.display());
            println!("log:        {}", log.display());
            println!("Run this again after upgrading webmcp or if your PATH changes.");
            if let Some(hint) = service::post_install_hint() {
                println!("{hint}");
            }
        }
        ServiceAction::Uninstall => {
            if service::uninstall(&home)? {
                println!(
                    "Stopped and removed the background service. Pairing and servers are kept."
                );
            } else {
                println!("The background service was not installed.");
            }
        }
        ServiceAction::Status if json => {
            let supported = service::supported();
            let st = if supported {
                service::status(&home)?
            } else {
                service::ServiceStatus {
                    installed: false,
                    pid: None,
                }
            };
            let report = output::ServiceStatusReport {
                supported,
                installed: st.installed,
                running: st.pid.is_some(),
                pid: st.pid,
                log: supported.then(|| service::log_path(&home).display().to_string()),
            };
            println!("{}", output::line(&report));
        }
        ServiceAction::Status => {
            let st = service::status(&home)?;
            match (st.installed, st.pid) {
                (false, _) => println!("not installed (run `webmcp service install`)"),
                (true, Some(pid)) => println!("running (pid {pid})"),
                (true, None) => println!(
                    "installed but not running; see {}",
                    service::log_path(&home).display()
                ),
            }
        }
    }
    Ok(())
}

fn status(dir: PathBuf, json: bool) -> Result<()> {
    let cfg = Config::try_load_from(&dir)?;
    if json {
        let config = Config::path_in(&dir).display().to_string();
        let fingerprint = keys::load(&dir)
            .ok()
            .map(|k| keys::fingerprint(&k.verifying_key()));
        let report = match cfg {
            None => output::StatusReport {
                paired: false,
                config,
                handle: None,
                device: None,
                device_id: None,
                key_fingerprint: None,
                base_url: None,
                relay_url: None,
                servers: None,
            },
            Some(c) => output::StatusReport {
                paired: true,
                config,
                handle: Some(c.handle),
                device: Some(c.device_name),
                device_id: Some(c.device_id),
                key_fingerprint: Some(fingerprint),
                base_url: Some(c.base_url),
                relay_url: Some(c.relay_url),
                servers: Some(c.servers.len()),
            },
        };
        println!("{}", output::line(&report));
        return Ok(());
    }
    println!("config:      {}", Config::path_in(&dir).display());
    let cfg = match cfg {
        Some(c) => c,
        None => {
            println!("state:       not paired (run `webmcp up`)");
            return Ok(());
        }
    };
    println!("handle:      {}", cfg.handle);
    println!("device id:   {}", cfg.device_id);
    println!("device name: {}", cfg.device_name);
    match keys::load(&dir) {
        Ok(key) => println!("key:         {}", keys::fingerprint(&key.verifying_key())),
        Err(Error::NotPaired) => println!("key:         missing ({} not found)", keys::KEY_FILE),
        Err(e) => println!("key:         unreadable ({e})"),
    }
    println!("relay:       {}", cfg.relay_url);
    println!("servers:     {}", cfg.servers.len());
    Ok(())
}

fn attach(dir: PathBuf, args: AttachArgs, json: bool) -> Result<()> {
    let mut cfg = load_config(&dir)?;
    let mut entry = match (args.stdio, args.http, args.command.is_empty()) {
        (Some(cmd), None, true) => ServerEntry::stdio(&args.alias, &cmd, args.mode)?,
        (None, None, false) => {
            ServerEntry::stdio(&args.alias, &shell_words::join(&args.command), args.mode)?
        }
        (None, Some(url), true) => ServerEntry::http(&args.alias, &url, args.mode)?,
        _ => bail!(
            "pass exactly one of --stdio \"<command>\", --http <url> or -- <command> [args...]"
        ),
    };
    for pair in &args.env {
        let (key, value) = parse_env(pair)?;
        entry.env.insert(key, value);
    }
    if let Some(cwd) = args.cwd {
        // Stored absolute: the daemon's own working directory will differ.
        let cwd =
            std::fs::canonicalize(&cwd).with_context(|| format!("--cwd {}", cwd.display()))?;
        if !cwd.is_dir() {
            bail!("--cwd {} is not a directory", cwd.display());
        }
        entry.cwd = Some(cwd);
    }
    entry.max_sessions = args.max_sessions.map(|n| n as usize);
    if entry.is_unsupported() {
        eprintln!("warning: {}", config::SHARED_STDIO_UNSUPPORTED);
    }
    let view = output::ServerView::new(&cfg, &entry);
    cfg.attach(entry)?;
    cfg.save_to(&dir)?;
    if json {
        println!("{}", output::line(&output::AttachReport { attached: view }));
        return Ok(());
    }
    println!(
        "Attached {} ({}, {}): {}",
        view.alias, view.transport, view.mode, view.target
    );
    if let Some(url) = &view.url {
        println!("URL: {url}");
    }
    println!("A running `webmcp connect` picks it up within a couple of seconds.");
    Ok(())
}

/// Split `KEY=VAL`; the key must be a plausible variable name.
fn parse_env(pair: &str) -> Result<(String, String)> {
    let Some((key, value)) = pair.split_once('=') else {
        bail!("--env `{pair}` must look like KEY=VAL");
    };
    let valid = !key.is_empty()
        && !key.starts_with(|c: char| c.is_ascii_digit())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        bail!("--env `{pair}`: `{key}` is not a valid variable name");
    }
    Ok((key.to_string(), value.to_string()))
}

fn detach(dir: PathBuf, alias: &str, json: bool) -> Result<()> {
    let mut cfg = load_config(&dir)?;
    let entry = cfg.detach(alias)?;
    cfg.save_to(&dir)?;
    if json {
        let detached = output::ServerView::new(&cfg, &entry);
        println!("{}", output::line(&output::DetachReport { detached }));
        return Ok(());
    }
    println!("Detached {} ({})", entry.alias, entry.transport);
    println!("A running `webmcp connect` drops it within a couple of seconds.");
    Ok(())
}

fn servers(dir: PathBuf, json: bool) -> Result<()> {
    let cfg = load_config(&dir)?;
    if json {
        let servers = cfg
            .servers
            .iter()
            .map(|s| output::ServerView::new(&cfg, s))
            .collect();
        println!("{}", output::line(&output::ServersReport { servers }));
        return Ok(());
    }
    if cfg.servers.is_empty() {
        println!("No servers attached. Try: webmcp attach <alias> -- <command> [args...]");
        return Ok(());
    }
    let width = cfg
        .servers
        .iter()
        .map(|s| s.alias.len())
        .max()
        .unwrap_or(5)
        .max(5);
    println!("{:<width$}  {:<6}  {:<11}  TARGET", "ALIAS", "KIND", "MODE");
    for s in &cfg.servers {
        println!(
            "{:<width$}  {:<6}  {:<11}  {}",
            s.alias,
            s.transport,
            s.mode,
            s.target()
        );
    }
    Ok(())
}
