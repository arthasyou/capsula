//! Capsula 密钥管理命令行工具

mod commands;
mod error;

use clap::{Parser, Subcommand};
use error::CliResult;

#[derive(Parser)]
#[command(name = "capsula")]
#[command(about = "Capsula 密钥管理工具 - 安全的密钥和签名管理")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 生成新的密钥对
    Generate {
        /// 密钥标识
        #[arg(short, long)]
        name: String,
        
        /// 密钥算法 (目前仅支持 ed25519)
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
        
        /// 输出目录
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// 签名文件或数据
    Sign {
        /// 要签名的文件路径
        #[arg(short, long)]
        file: String,
        
        /// 私钥文件路径
        #[arg(short, long)]
        key: String,
        
        /// 签名输出文件
        #[arg(short, long)]
        output: Option<String>,
        
        /// 签名者信息
        #[arg(long)]
        signer: Option<String>,
        
        /// 签名位置
        #[arg(long)]
        location: Option<String>,
    },
    
    /// 验证签名
    Verify {
        /// 要验证的文件路径
        #[arg(short, long)]
        file: String,
        
        /// 签名文件路径
        #[arg(short, long)]
        signature: String,
    },
    
    /// 计算文件哈希
    Hash {
        /// 要计算哈希的文件
        #[arg(short, long)]
        file: String,
        
        /// 哈希算法 (sha256 或 sha512)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
    },
    
    /// 导出公钥
    Export {
        /// 私钥文件路径
        #[arg(short, long)]
        key: String,
        
        /// 公钥输出路径
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// 显示密钥信息
    Info {
        /// 密钥文件路径
        #[arg(short, long)]
        key: String,
    },
}

fn main() -> CliResult<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { name, algorithm, output } => {
            commands::generate::handle(name, algorithm, output)?;
        }
        Commands::Sign { file, key, output, signer, location } => {
            commands::sign::handle(file, key, output, signer, location)?;
        }
        Commands::Verify { file, signature } => {
            commands::verify::handle(file, signature)?;
        }
        Commands::Hash { file, algorithm } => {
            commands::hash::handle(file, algorithm)?;
        }
        Commands::Export { key, output } => {
            commands::export::handle(key, output)?;
        }
        Commands::Info { key } => {
            commands::info::handle(key)?;
        }
    }
    
    Ok(())
}