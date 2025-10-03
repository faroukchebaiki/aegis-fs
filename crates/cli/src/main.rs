use std::path::PathBuf;

use aegis_core::model::DefaultsConfig;
use aegis_core::storage::httpbucket;
use aegis_core::store::FileStore;
use aegis_core::util::resolve_home;
use aegis_core::{AegisFs, PackOptions, UnpackOptions};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser, Debug)]
#[command(
    name = "aegis-fs",
    version,
    about = "Phase 1 local scaffolding for aegis-fs"
)]
struct Cli {
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init(InitArgs),
    SetCache(SetCacheArgs),
    Pack(PackArgs),
    Unpack(UnpackArgs),
    List,
    Show(ShowArgs),
    Rm(RemoveArgs),
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    Upload(UploadArgs),
    Fetch(FetchArgs),
    GcRemote(GcRemoteArgs),
}

#[derive(Parser, Debug)]
struct InitArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    confirm_password: Option<String>,
    #[arg(long)]
    k: Option<u8>,
    #[arg(long)]
    m: Option<u8>,
    #[arg(long = "cache-gb")]
    cache_gb: Option<u32>,
}

#[derive(Parser, Debug)]
struct SetCacheArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(value_name = "GB")]
    cache_gb: u32,
}

#[derive(Parser, Debug)]
struct PackArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(value_name = "SRC")]
    source: PathBuf,
    #[arg(long = "id")]
    file_id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    k: Option<u8>,
    #[arg(long)]
    m: Option<u8>,
    #[arg(long)]
    compress: bool,
}

#[derive(Parser, Debug)]
struct UnpackArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "id")]
    file_id: String,
    #[arg(value_name = "DEST")]
    destination: PathBuf,
    #[arg(long)]
    overwrite: bool,
    #[arg(long = "from-remote")]
    from_remote: bool,
    #[arg(long)]
    account: Option<String>,
}

#[derive(Parser, Debug)]
struct ShowArgs {
    #[arg(long = "id")]
    file_id: String,
}

#[derive(Parser, Debug)]
struct RemoveArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "id")]
    file_id: String,
}

#[derive(Subcommand, Debug)]
enum AccountCommand {
    Add(AccountAddArgs),
    List(AccountListArgs),
    SetWeight(AccountSetWeightArgs),
}

#[derive(Parser, Debug)]
struct AccountAddArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long, default_value = httpbucket::BACKEND_ID)]
    backend: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Parser, Debug)]
struct AccountListArgs {
    #[arg(long)]
    verbose: bool,
}

#[derive(Parser, Debug)]
struct AccountSetWeightArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    weight: i64,
}

#[derive(Parser, Debug)]
struct UploadArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "id")]
    file_id: String,
    #[arg(long = "plan-only")]
    plan_only: bool,
    #[arg(long, hide = true)]
    seed: Option<u64>,
}

#[derive(Parser, Debug)]
struct FetchArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "id")]
    file_id: String,
    #[arg(value_name = "DEST")]
    destination: PathBuf,
    #[arg(long)]
    overwrite: bool,
    #[arg(long)]
    account: Option<String>,
}

#[derive(Parser, Debug)]
struct GcRemoteArgs {
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "id")]
    file_id: String,
    #[arg(long)]
    account: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let home_paths = resolve_home(cli.home.as_deref())?;

    match cli.command {
        Commands::Init(args) => handle_init(home_paths, args).await,
        Commands::SetCache(args) => handle_set_cache(home_paths, args).await,
        Commands::Pack(args) => handle_pack(home_paths, args).await,
        Commands::Unpack(args) => handle_unpack(home_paths, args).await,
        Commands::List => handle_list(home_paths).await,
        Commands::Show(args) => handle_show(home_paths, args).await,
        Commands::Rm(args) => handle_remove(home_paths, args).await,
        Commands::Account { command } => handle_account(home_paths, command).await,
        Commands::Upload(args) => handle_upload(home_paths, args).await,
        Commands::Fetch(args) => handle_fetch(home_paths, args).await,
        Commands::GcRemote(args) => handle_gc_remote(home_paths, args).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("aegis_core=info,aegis_cli=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn handle_init(home_paths: aegis_core::util::HomePaths, args: InitArgs) -> Result<()> {
    let mut password = resolve_password_with_confirm(args.password, args.confirm_password)?;
    let defaults = DefaultsConfig {
        k: args.k.unwrap_or(10),
        m: args.m.unwrap_or(4),
        cache_gb: args.cache_gb.unwrap_or(10),
    };
    let result = AegisFs::init(home_paths.clone(), password.as_ref(), defaults).await;
    password.zeroize();
    result?;
    println!("Initialised aegis-fs home at {}", home_paths.base.display());
    Ok(())
}

async fn handle_set_cache(
    home_paths: aegis_core::util::HomePaths,
    args: SetCacheArgs,
) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths.clone()).await?;
    fs.set_cache(password.as_ref(), args.cache_gb).await?;
    println!("Cache updated to {} GiB", args.cache_gb);
    Ok(())
}

async fn handle_pack(home_paths: aegis_core::util::HomePaths, args: PackArgs) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths.clone()).await?;
    let options = PackOptions {
        source: args.source,
        file_id: args.file_id,
        name: args.name,
        k: args.k,
        m: args.m,
        compress: args.compress,
    };
    fs.pack(password.as_ref(), options).await?;
    println!("Pack completed");
    Ok(())
}

async fn handle_unpack(home_paths: aegis_core::util::HomePaths, args: UnpackArgs) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths.clone()).await?;
    let options = UnpackOptions {
        file_id: args.file_id,
        destination: args.destination,
        overwrite: args.overwrite,
        from_remote: args.from_remote,
        account: args.account,
    };
    let path = fs.unpack(password.as_ref(), options).await?;
    println!("Unpacked to {}", path.display());
    Ok(())
}

async fn handle_list(home_paths: aegis_core::util::HomePaths) -> Result<()> {
    let fs = AegisFs::load(home_paths.clone()).await?;
    let files = fs.list().await?;
    if files.is_empty() {
        println!("No files tracked");
    } else {
        for file in files {
            println!(
                "{}\t{} bytes\t{}",
                file.id,
                file.size,
                file.name.as_deref().unwrap_or("<unnamed>")
            );
        }
    }
    Ok(())
}

async fn handle_show(home_paths: aegis_core::util::HomePaths, args: ShowArgs) -> Result<()> {
    let fs = AegisFs::load(home_paths.clone()).await?;
    let details = fs.show(&args.file_id).await?;
    let store = FileStore::new(home_paths.objects_dir.clone());
    let meta = store.read_meta(&args.file_id).await?;
    println!("ID: {}", details.record.id);
    if let Some(name) = &details.record.name {
        println!("Name: {name}");
    }
    println!("Size: {} bytes", details.record.size);
    println!("Created: {}", details.record.created_at);
    println!("k/m: {}/{}", details.record.k, details.record.m);
    println!("Compressed: {}", details.record.compressed);
    println!("Ciphertext bytes: {}", meta.ciphertext_size);
    println!("Shards: {}", meta.checksums.len());
    Ok(())
}

async fn handle_remove(home_paths: aegis_core::util::HomePaths, args: RemoveArgs) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths).await?;
    fs.remove(password.as_ref(), &args.file_id).await?;
    println!("Removed {}", args.file_id);
    Ok(())
}

async fn handle_account(
    home_paths: aegis_core::util::HomePaths,
    cmd: AccountCommand,
) -> Result<()> {
    match cmd {
        AccountCommand::Add(args) => {
            let mut password = resolve_password("Master password", args.password)?;
            let token = if let Some(tok) = args.token {
                Zeroizing::new(tok)
            } else {
                Zeroizing::new(prompt_password("Bearer token: ").context("reading token")?)
            };
            let fs = AegisFs::load(home_paths).await?;
            let account_id = fs
                .add_account(
                    password.as_ref(),
                    &args.name,
                    &args.backend,
                    &args.endpoint,
                    token.as_ref(),
                )
                .await?;
            password.zeroize();
            println!("Account '{}' registered (id {})", args.name, account_id);
        }
        AccountCommand::List(args) => {
            let password = resolve_password("Master password", None)?;
            let fs = AegisFs::load(home_paths).await?;
            let accounts = fs.list_accounts(password.as_ref()).await?;
            if accounts.is_empty() {
                println!("No remote accounts configured");
            } else {
                for entry in accounts {
                    if args.verbose {
                        println!(
                            "{name}\tbackend={backend}\tendpoint={endpoint}\tweight={weight}\tsuccess_rate={rate:.2}\tlast_error={error}\ttoken={token}",
                            name = entry.record.name,
                            backend = entry.record.backend,
                            endpoint = entry.record.endpoint,
                            weight = entry.record.weight,
                            rate = entry.record.success_rate,
                            error = entry
                                .record
                                .last_error
                                .as_deref()
                                .unwrap_or("-"),
                            token = if entry.has_token { "stored" } else { "missing" }
                        );
                    } else {
                        println!(
                            "{}\tbackend={}\tendpoint={}\ttoken={}",
                            entry.record.name,
                            entry.record.backend,
                            entry.record.endpoint,
                            if entry.has_token { "stored" } else { "missing" }
                        );
                    }
                }
            }
        }
        AccountCommand::SetWeight(args) => {
            anyhow::ensure!(args.weight > 0, "weight must be > 0");
            let mut password = resolve_password("Master password", args.password)?;
            let fs = AegisFs::load(home_paths).await?;
            fs.set_account_weight(password.as_ref(), &args.name, args.weight)
                .await?;
            password.zeroize();
            println!("Updated weight for '{}' to {}", args.name, args.weight);
        }
    }
    Ok(())
}

async fn handle_upload(home_paths: aegis_core::util::HomePaths, args: UploadArgs) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths).await?;
    if args.plan_only {
        let plan = fs
            .plan_upload(password.as_ref(), &args.file_id, args.seed)
            .await?;
        if plan.is_empty() {
            println!("No shards to plan for {}", args.file_id);
        } else {
            println!("Placement plan for {}:", args.file_id);
            for entry in plan {
                println!(
                    "shard {:03} -> account {} (id {}) locator={} size={} bytes",
                    entry.shard_index,
                    entry.account_name,
                    entry.account_id,
                    entry.remote_ref,
                    entry.size
                );
            }
        }
    } else {
        fs.upload_shards(password.as_ref(), &args.file_id)
            .await?;
        println!("Uploaded shards for {}", args.file_id);
    }
    Ok(())
}

async fn handle_fetch(home_paths: aegis_core::util::HomePaths, args: FetchArgs) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths.clone()).await?;
    let options = UnpackOptions {
        file_id: args.file_id,
        destination: args.destination,
        overwrite: args.overwrite,
        from_remote: true,
        account: args.account,
    };
    let output = fs.unpack(password.as_ref(), options).await?;
    println!("Fetched and unpacked to {}", output.display());
    Ok(())
}

async fn handle_gc_remote(
    home_paths: aegis_core::util::HomePaths,
    args: GcRemoteArgs,
) -> Result<()> {
    let password = resolve_password("Master password", args.password)?;
    let fs = AegisFs::load(home_paths).await?;
    fs.gc_remote(password.as_ref(), &args.file_id, args.account.as_deref())
        .await?;
    println!("Removed remote shards for {}", args.file_id);
    Ok(())
}

fn resolve_password(prompt: &str, provided: Option<String>) -> Result<Zeroizing<String>> {
    if let Some(pass) = provided {
        return Ok(Zeroizing::new(pass));
    }
    let entered = prompt_password(format!("{prompt}: ").as_str()).context("reading password")?;
    Ok(Zeroizing::new(entered))
}

fn resolve_password_with_confirm(
    provided: Option<String>,
    confirm: Option<String>,
) -> Result<Zeroizing<String>> {
    if let Some(pass) = provided {
        if let Some(confirm) = confirm {
            anyhow::ensure!(pass == confirm, "password confirmation mismatch");
        }
        return Ok(Zeroizing::new(pass));
    }
    let pass = prompt_password("Master password: ").context("reading password")?;
    let confirm_pass = prompt_password("Confirm master password: ").context("reading password")?;
    anyhow::ensure!(pass == confirm_pass, "password confirmation mismatch");
    Ok(Zeroizing::new(pass))
}
