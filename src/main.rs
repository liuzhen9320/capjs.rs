//! # Proof-of-Work Solver CLI
//!
//! A high-performance, parallel proof-of-work solver implemented in Rust.
//! This crate provides functionality to solve cryptographic proof-of-work challenges
//! using SHA-256 hashing with customizable difficulty targets.
//!
//! ## Features
//!
//! - **Single Challenge Solving**: Solve individual proof-of-work challenges
//! - **Batch Processing**: Generate and solve multiple challenges in parallel
//! - **JSON Support**: Import/export challenges in JSON format
//! - **Multi-threading**: Configurable worker threads for optimal performance
//! - **Progress Tracking**: Visual progress bars for long-running operations
//! - **Flexible Output**: Plain text or JSON output formats
//!
//! ## Examples
//!
//! ### Solving a Single Challenge
//!
//! ```rust
//! use pow_solver::solve_pow;
//!
//! let salt = "mysalt123";
//! let target = "00000a";
//! let nonce = solve_pow(salt, target);
//! println!("Found nonce: {}", nonce);
//! ```
//!
//! ### Batch Challenge Generation
//!
//! ```bash
//! pow-solver multi -t "mytoken" -c 10 -d 6 -w 8
//! ```

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Main CLI application structure for the proof-of-work solver.
///
/// This struct defines the command-line interface using the `clap` crate,
/// providing subcommands for different solving modes.
#[derive(Parser)]
#[command(name = "pow-solver")]
#[command(about = "A blazingly fast, parallel Capjs proof-of-work solver implemented in Rust")]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands for the proof-of-work solver.
///
/// Each variant represents a different mode of operation:
/// - `Single`: Solve one challenge with provided salt and target
/// - `Multi`: Generate and solve multiple challenges from a seed
/// - `Json`: Solve challenges from JSON input
#[derive(Subcommand)]
enum Commands {
    /// Solve a single challenge
    ///
    /// This command solves a single proof-of-work challenge using
    /// the provided salt and target hash prefix.
    Single {
        /// Salt value used as input to the hash function
        ///
        /// The salt is combined with incrementing nonce values
        /// to find a hash matching the target prefix.
        #[arg(short, long)]
        salt: String,
        
        /// Target hash prefix (in hexadecimal)
        ///
        /// The hash must start with this prefix. Longer prefixes
        /// increase difficulty exponentially.
        #[arg(short, long)]
        target: String,
    },
    
    /// Solve multiple challenges
    ///
    /// Generates multiple challenges from a seed token and solves
    /// them in parallel using configurable worker threads.
    Multi {
        /// Challenge string to generate from (token)
        ///
        /// Used as a seed to generate deterministic salt and target
        /// values for multiple challenges.
        #[arg(short = 't', long)]
        challenge: String,
        
        /// Number of challenges to generate
        ///
        /// Each challenge will have a unique salt/target pair
        /// generated from the challenge token.
        #[arg(short = 'c', long, default_value = "1")]
        count: usize,
        
        /// Salt length in characters
        ///
        /// Determines the length of the generated salt strings.
        /// Longer salts provide more entropy.
        #[arg(short = 's', long, default_value = "32")]
        salt_length: usize,
        
        /// Target length in hex characters
        ///
        /// Determines the difficulty of the proof-of-work.
        /// Each additional character increases difficulty by 16x.
        #[arg(short = 'd', long, default_value = "6")]
        target_length: usize,
        
        /// Number of worker threads (0 = auto)
        ///
        /// Controls parallel execution. 0 uses all available CPU cores.
        #[arg(short = 'w', long, default_value = "0")]
        workers: usize,
        
        /// Output format (json, json_pretty, plain)
        ///
        /// - `plain`: Human-readable text output
        /// - `json`: Compact JSON output
        /// - `json_pretty`: Pretty-printed JSON output
        #[arg(short, long, default_value = "plain")]
        output: String,
    },
    
    /// Solve from JSON input
    ///
    /// Accepts a JSON array of [salt, target] pairs and solves
    /// each challenge in parallel.
    Json {
        /// JSON string containing challenges [[salt, target], ...]
        ///
        /// Format: `[["salt1", "target1"], ["salt2", "target2"]]`
        #[arg(short, long)]
        input: String,
        
        /// Number of worker threads (0 = auto)
        ///
        /// Controls parallel execution. 0 uses all available CPU cores.
        #[arg(short = 'w', long, default_value = "0")]
        workers: usize,
    },
}

/// Result of solving a single proof-of-work challenge.
///
/// Contains all relevant information about the solved challenge,
/// including timing data for performance analysis.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChallengeResult {
    /// Index of the challenge in the batch (0-based)
    challenge_index: usize,
    
    /// Salt value used in the challenge
    salt: String,
    
    /// Target hash prefix that was matched
    target: String,
    
    /// Nonce value that produces the matching hash
    nonce: u64,
    
    /// Time taken to solve the challenge in seconds
    duration: f64,
}

/// Main entry point for the CLI application.
///
/// Parses command-line arguments and dispatches to the appropriate
/// solving function based on the selected subcommand.
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

/// Solves a single proof-of-work challenge.
///
/// This function implements the core proof-of-work algorithm by iterating
/// through nonce values until a hash is found that matches the target prefix.
/// The algorithm uses SHA-256 hashing and optimized buffer operations for
/// maximum performance.
///
/// # Arguments
///
/// * `salt` - The salt string to be combined with the nonce
/// * `target` - The target hash prefix in hexadecimal format
///
/// # Returns
///
/// The nonce value (u64) that, when combined with the salt and hashed,
/// produces a hash with the specified prefix.
///
/// # Examples
///
/// ```rust
/// use pow_solver::solve_pow;
///
/// let nonce = solve_pow("mysalt", "0000");
/// println!("Found nonce: {}", nonce);
/// ```
///
/// # Performance Notes
///
/// - Uses optimized buffer operations to avoid string allocations
/// - Implements early termination when target is matched
/// - Time complexity depends on target difficulty (exponential)
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

/// Solves multiple proof-of-work challenges in parallel.
///
/// This function distributes the solving work across multiple threads
/// using the Rayon parallel processing library. It provides progress
/// tracking and collects timing information for each challenge.
///
/// # Arguments
///
/// * `challenges` - Vector of (salt, target) tuples to solve
/// * `worker_count` - Number of worker threads to use
/// * `show_progress` - Whether to display a progress bar
///
/// # Returns
///
/// Vector of `ChallengeResult` containing solve results and timing data.
///
/// # Examples
///
/// ```rust
/// let challenges = vec![
///     ("salt1".to_string(), "0000".to_string()),
///     ("salt2".to_string(), "0001".to_string()),
/// ];
/// let results = solve_multiple_challenges(challenges, 4, true);
/// ```
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

/// Pseudo-random number generator compatible with JavaScript implementation.
///
/// This function generates deterministic pseudo-random strings using
/// a combination of FNV-1a hashing and a linear congruential generator.
/// It ensures compatibility with existing JavaScript-based challenge
/// generation systems.
///
/// # Arguments
///
/// * `seed` - Input string used to seed the generator
/// * `length` - Desired length of the output string
///
/// # Returns
///
/// A hexadecimal string of the specified length.
///
/// # Algorithm Details
///
/// 1. Uses FNV-1a hash to generate initial state from seed
/// 2. Applies xorshift operations for pseudo-randomness
/// 3. Converts state to hexadecimal representation
/// 4. Repeats until desired length is reached
fn prng(seed: &str, length: usize) -> String {
    /// FNV-1a hash function implementation.
    ///
    /// A fast, non-cryptographic hash function that provides
    /// good distribution properties for hash table applications.
    ///
    /// # Arguments
    ///
    /// * `s` - Input string to hash
    ///
    /// # Returns
    ///
    /// 32-bit hash value
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

/// Generates multiple challenge pairs from a seed token.
///
/// Creates deterministic salt and target pairs for batch processing.
/// Each challenge is generated using a unique index combined with
/// the base challenge token to ensure reproducible results.
///
/// # Arguments
///
/// * `challenge` - Base challenge token for generation
/// * `count` - Number of challenge pairs to generate
/// * `salt_length` - Length of generated salt strings
/// * `target_length` - Length of generated target strings
///
/// # Returns
///
/// Vector of (salt, target) string tuples.
///
/// # Generation Algorithm
///
/// - Salt: Generated from `{challenge}{index}`
/// - Target: Generated from `{challenge}{index}d`
///
/// The 'd' suffix for targets ensures different entropy sources
/// for salt and target generation.
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

/// Parses a hexadecimal target string into bytes.
///
/// Converts a hexadecimal target string into a byte array for
/// efficient comparison during hash matching. Handles odd-length
/// strings by padding with a trailing zero.
///
/// # Arguments
///
/// * `target` - Hexadecimal target string
///
/// # Returns
///
/// Vector of bytes representing the target.
///
/// # Examples
///
/// ```rust
/// let target_bytes = parse_hex_target("ff00a1");
/// assert_eq!(target_bytes, vec![0xff, 0x00, 0xa1]);
/// ```
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

/// Writes a u64 value to a byte buffer as ASCII digits.
///
/// High-performance function to convert integers to ASCII
/// representation without heap allocation. Used to avoid
/// string allocation overhead in the tight proof-of-work loop.
///
/// # Arguments
///
/// * `value` - The u64 value to convert
/// * `buffer` - Byte buffer to write into (must be at least 20 bytes)
///
/// # Returns
///
/// Number of bytes written to the buffer.
///
/// # Performance Notes
///
/// - Zero-allocation conversion
/// - Optimized for repeated calls in hot loops
/// - Handles edge case of value = 0
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

/// Checks if a hash matches the target prefix.
///
/// Performs efficient bit-level comparison between a computed hash
/// and the target prefix, supporting arbitrary bit-length targets.
/// This allows for fine-grained difficulty adjustment beyond
/// byte boundaries.
///
/// # Arguments
///
/// * `hash` - The computed hash bytes
/// * `target_bytes` - Target prefix as bytes
/// * `target_bits` - Number of bits to compare (for sub-byte precision)
///
/// # Returns
///
/// `true` if the hash matches the target prefix, `false` otherwise.
///
/// # Algorithm Details
///
/// 1. Compares full bytes first for efficiency
/// 2. Handles partial byte comparison using bit masks
/// 3. Supports targets that don't align to byte boundaries
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

/// Simple CPU count implementation to avoid extra dependencies.
///
/// This module provides a minimal implementation for detecting
/// the number of available CPU cores without requiring additional
/// dependencies beyond the standard library.
mod num_cpus {
    /// Returns the number of available CPU cores.
    ///
    /// Uses the standard library's `available_parallelism()` function
    /// with fallback to 1 if detection fails.
    ///
    /// # Returns
    ///
    /// Number of available CPU cores (minimum 1).
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}