use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "pow-solver")]
#[command(about = "A Proof-of-Work solver CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Solve a single challenge
    Single {
        /// Salt value
        #[arg(short, long)]
        salt: String,
        /// Target hash prefix
        #[arg(short, long)]
        target: String,
    },
    /// Solve multiple challenges
    Multi {
        /// Challenge string to generate from (token)
        #[arg(short = 't', long)]
        challenge: String,
        /// Number of challenges to generate
        #[arg(short = 'c', long, default_value = "1")]
        count: usize,
        /// Salt length
        #[arg(short = 's', long, default_value = "32")]
        salt_length: usize,
        /// Target length
        #[arg(short = 'd', long, default_value = "6")]
        target_length: usize,
        /// Number of worker threads (0 = auto)
        #[arg(short = 'w', long, default_value = "0")]
        workers: usize,
        /// Output format (json, plain)
        #[arg(short, long, default_value = "plain")]
        output: String,
    },
    /// Solve from JSON input
    Json {
        /// JSON string containing challenges [[salt, target], ...]
        #[arg(short, long)]
        input: String,
        /// Number of worker threads (0 = auto)
        #[arg(short = 'w', long, default_value = "0")]
        workers: usize,
    },
}

#[derive(Serialize, Deserialize)]
struct ChallengeResult {
    challenge_index: usize,
    salt: String,
    target: String,
    nonce: u64,
    duration: f64,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Single { salt, target } => {
            let start_time = Instant::now();
            let nonce = solve_pow(&salt, &target);
            let duration = start_time.elapsed().as_secs_f64();

            println!("Salt: {}", salt);
            println!("Target: {}", target);
            println!("Nonce: {}", nonce);
            println!("Duration: {} ms", duration * 1000.0);
        }
        Commands::Multi {
            challenge,
            count,
            salt_length,
            target_length,
            workers,
            output,
        } => {
            let challenges = generate_challenges(&challenge, count, salt_length, target_length);
            let worker_count = if workers == 0 {
                num_cpus::get()
            } else {
                workers
            };
            let show_progress = output != "json" && output != "json_pretty";
            let results = solve_multiple_challenges(challenges, worker_count, show_progress);

            if output == "json" {
                println!("{}", serde_json::to_string(&results).unwrap());
            } else if output == "json_pretty" {
                println!("{}", serde_json::to_string_pretty(&results).unwrap());
            } else {
                for result in results {
                    println!(
                        "Challenge {}: salt={}, target={}, nonce={}, duration={:.3}s",
                        result.challenge_index,
                        result.salt,
                        result.target,
                        result.nonce,
                        result.duration
                    );
                }
            }
        }
        Commands::Json { input, workers } => {
            let challenges: Vec<(String, String)> = serde_json::from_str(&input)
                .expect("Invalid JSON format. Expected array of [salt, target] pairs");

            let worker_count = if workers == 0 {
                num_cpus::get()
            } else {
                workers
            };
            let results = solve_multiple_challenges(challenges, worker_count, true);

            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
    }
}

pub fn solve_pow(salt: &str, target: &str) -> u64 {
    let salt_bytes = salt.as_bytes();
    let target_bytes = parse_hex_target(target);
    let target_bits = target.len() * 4; // each hex char = 4 bits
    let mut nonce_buffer = [0u8; 20]; // u64::MAX has at most 20 digits

    for nonce in 0..u64::MAX {
        let nonce_len = write_u64_to_buffer(nonce, &mut nonce_buffer);
        let nonce_bytes = &nonce_buffer[..nonce_len];

        let mut hasher = Sha256::new();
        hasher.update(salt_bytes);
        hasher.update(nonce_bytes);
        let hash_result = hasher.finalize();

        if hash_matches_target(&hash_result, &target_bytes, target_bits) {
            return nonce;
        }
    }

    unreachable!("Solution should be found before exhausting u64::MAX");
}

fn solve_multiple_challenges(
    challenges: Vec<(String, String)>,
    worker_count: usize,
    show_progress: bool,
) -> Vec<ChallengeResult> {
    let total_challenges = challenges.len();

    let progress_bar = if show_progress {
        let pb = ProgressBar::new(total_challenges as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Configure rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()
        .unwrap();

    let results = pool.install(|| {
        challenges
            .into_par_iter()
            .enumerate()
            .map(|(index, (salt, target))| {
                let start_time = Instant::now();
                let nonce = solve_pow(&salt, &target);
                let duration = start_time.elapsed().as_secs_f64();

                if let Some(ref pb) = progress_bar {
                    pb.inc(1);
                }

                ChallengeResult {
                    challenge_index: index,
                    salt,
                    target,
                    nonce,
                    duration,
                }
            })
            .collect()
    });

    if let Some(pb) = progress_bar {
        pb.finish_with_message("Completed!");
    }

    results
}

// PRNG implementation matching the JavaScript version
fn prng(seed: &str, length: usize) -> String {
    fn fnv1a(s: &str) -> u32 {
        let mut hash = 2166136261u32;
        for byte in s.bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(16777619);
        }
        hash
    }

    let mut state = fnv1a(seed);
    let mut result = String::new();

    while result.len() < length {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;

        result.push_str(&format!("{:08x}", state));
    }

    result.chars().take(length).collect()
}

fn generate_challenges(
    challenge: &str,
    count: usize,
    salt_length: usize,
    target_length: usize,
) -> Vec<(String, String)> {
    (1..=count)
        .map(|i| {
            let salt = prng(&format!("{}{}", challenge, i), salt_length);
            let target = prng(&format!("{}{}d", challenge, i), target_length);
            (salt, target)
        })
        .collect()
}

fn parse_hex_target(target: &str) -> Vec<u8> {
    let mut padded_target = target.to_string();

    if padded_target.len() % 2 != 0 {
        padded_target.push('0');
    }

    (0..padded_target.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded_target[i..i + 2], 16).unwrap())
        .collect()
}

fn write_u64_to_buffer(mut value: u64, buffer: &mut [u8]) -> usize {
    if value == 0 {
        buffer[0] = b'0';
        return 1;
    }

    let mut len = 0;
    let mut temp = value;

    while temp > 0 {
        len += 1;
        temp /= 10;
    }

    for i in (0..len).rev() {
        buffer[i] = (value % 10) as u8 + b'0';
        value /= 10;
    }

    len
}

fn hash_matches_target(hash: &[u8], target_bytes: &[u8], target_bits: usize) -> bool {
    let full_bytes = target_bits / 8;
    let remaining_bits = target_bits % 8;

    if hash[..full_bytes] != target_bytes[..full_bytes] {
        return false;
    }

    if remaining_bits > 0 && full_bytes < target_bytes.len() {
        let mask = 0xFF << (8 - remaining_bits);
        let hash_masked = hash[full_bytes] & mask;
        let target_masked = target_bytes[full_bytes] & mask;
        return hash_masked == target_masked;
    }

    true
}

// Simple CPU count implementation to avoid extra dependencies
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}
