# ⛏️ CapJS Proof-of-Work Solver CLI

> 🚀 A blazingly fast, parallel Capjs proof-of-work solver implemented in Rust

## ✨ Features

- 🎯 **Single Challenge Solving**: Solve individual proof-of-work challenges with precision
- 📦 **Batch Processing**: Generate and solve thousands of challenges in parallel
- 🔧 **JSON Support**: Import/export challenges in structured JSON format
- 🧵 **Multi-threading**: Configurable worker threads for maximum CPU utilization
- 📊 **Progress Tracking**: Beautiful progress bars with ETA for long operations
- 🎨 **Flexible Output**: Choose between plain text, JSON, or pretty-printed formats
- ⚡ **Zero-Copy Operations**: Optimized buffer operations for maximum performance
- 🔒 **SHA-256 Hashing**: Industry-standard cryptographic hashing

## 🛠️ Installation

### From Source

```bash
git clone https://github.com/liuzhen9320/capjs-cli.git
cd capjs-cli
cargo install --path .
```

### Pre-built Binaries

Download the latest release from our [GitHub Releases](https://github.com/liuzhen9320/capjs-cli/releases) page.

## 🚀 Quick Start

### 🎯 Solve a Single Challenge

```bash
# Basic usage
pow-solver single --salt "a5b6fda4aaed97cf61d7dd9259f733b5" --target "d455"

# Output:
# Salt: a5b6fda4aaed97cf61d7dd9259f733b5
# Target: d455
# Nonce: 67302
# Duration: 371.226518 ms
```

### 📦 Generate and Solve Multiple Challenges

```bash
# Standard web page validation. The data here can be obtained from the http://API_HOST/API_KEY/challenge endpoint
pow-solver multi -c 50 -d 4 -s 32 -t 4097a4371e6852602a1b7d91bd4eccf5e356365756fef135b9

# More scientific, using JSON output for easier parsing
pow-solver multi -c 50 -d 4 -s 32 -t 4097a4371e6852602a1b7d91bd4eccf5e356365756fef135b9 -o json
```

## 🎨 Output Formats

### Plain Text (Default)

```
Challenge 0: salt=a1b2c3, target=000012, nonce=87654, duration=0.234s
Challenge 1: salt=d4e5f6, target=000034, nonce=12345, duration=0.456s
```

### JSON Compact

```json
[
  {
    "challenge_index": 0,
    "salt": "a1b2c3",
    "target": "000012",
    "nonce": 87654,
    "duration": 0.234
  }
]
```

### JSON Pretty

```json
[
  {
    "challenge_index": 0,
    "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "target": "000012",
    "nonce": 87654,
    "duration": 0.234
  }
]
```

## ⚙️ Command Reference

### 🎯 `single` - Solve Single Challenge

| Flag           | Description             | Example              |
| -------------- | ----------------------- | -------------------- |
| `-s, --salt`   | Salt string for hashing | `--salt "mysalt123"` |
| `-t, --target` | Target hex prefix       | `--target "00000a"`  |

### 📦 `multi` - Batch Processing

| Flag                  | Default  | Description               |
| --------------------- | -------- | ------------------------- |
| `-t, --challenge`     | Required | Seed token for generation |
| `-c, --count`         | `1`      | Number of challenges      |
| `-s, --salt-length`   | `32`     | Generated salt length     |
| `-d, --target-length` | `6`      | Target difficulty length  |
| `-w, --workers`       | `0`      | Worker threads (0=auto)   |
| `-o, --output`        | `plain`  | Output format             |

### 📋 `json` - JSON Input Mode

| Flag            | Default  | Description             |
| --------------- | -------- | ----------------------- |
| `-i, --input`   | Required | JSON challenge array    |
| `-w, --workers` | `0`      | Worker threads (0=auto) |

## 🧮 Difficulty Guide

Understanding target difficulty:

| Length | Avg Attempts | Difficulty   | Use Case            |
| ------ | ------------ | ------------ | ------------------- |
| 3      | ~4K          | 🟢 Easy      | Development/Testing |
| 4      | ~65K         | 🟡 Medium    | Small-scale mining  |
| 5      | ~1M          | 🟠 Hard      | Production use      |
| 6      | ~16M         | 🔴 Very Hard | High security       |
| 7      | ~268M        | ⚫ Extreme   | Enterprise/Research |

> 💡 **Tip**: Each additional hex character increases difficulty by ~16x

## 🤝 Contributing

We welcome contributions!

### 🐛 Found a Bug?

1. 🔍 Check [existing issues](https://github.com/liuzhen9320/capjs-cli/issues)
2. 📝 Create a detailed bug report
3. 🏷️ Add appropriate labels

### 💡 Feature Requests

1. 💭 Open an issue with the "enhancement" label
2. 📋 Describe the use case and benefits
3. 🤝 Discuss implementation approaches

## Third-Party Libraries Used

### @cap.js/wasm

- Source: <https://github.com/tiagozip/cap>
- License: Apache License 2.0

This project uses this library and complies with the requirements of the Apache-2.0 license. The full license text is included in the appendix.