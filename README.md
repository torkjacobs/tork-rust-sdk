# Tork Governance Rust SDK

On-device AI governance SDK with PII detection, redaction, and cryptographic receipts.

[![Crates.io](https://img.shields.io/crates/v/tork-governance.svg)](https://crates.io/crates/tork-governance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tork-governance = "0.1.0"
```

## Quick Start

```rust
use tork_governance::{Tork, GovernanceAction};

fn main() {
    let mut tork = Tork::new();

    // Govern text - detects and redacts PII
    let result = tork.govern("My SSN is 123-45-6789");

    assert_eq!(result.action, GovernanceAction::Redact);
    assert_eq!(result.output, "My SSN is [SSN_REDACTED]");
    println!("Receipt ID: {}", result.receipt.receipt_id);
}
```

## Regional PII Detection (v1.1)

Activate country-specific and industry-specific PII patterns:

```rust
use tork_governance::{Tork, GovernOptions};

let mut tork = Tork::new();

// UAE regional detection — Emirates ID, +971 phone, PO Box
let result = tork.govern_with_options(
    "Emirates ID: 784-1234-1234567-1",
    GovernOptions { region: Some(vec!["ae".into()]), ..Default::default() },
);

// Multi-region + industry
let result = tork.govern_with_options(
    "Aadhaar: 1234 5678 9012, ICD-10: J45.20",
    GovernOptions {
        region: Some(vec!["in".into()]),
        industry: Some("healthcare".into()),
    },
);

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## Supported Frameworks (3 Adapters)

### Web Frameworks
- **Actix-web** - Middleware for Actix-web
- **Axum** - Layer/middleware for Axum
- **Rocket** - Fairing for Rocket

## Framework Examples

### Actix-web Middleware

```rust
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use tork_governance::middleware::actix::TorkMiddleware;

async fn chat(req: HttpRequest) -> HttpResponse {
    // Access governance result from request extensions
    if let Some(result) = req.extensions().get::<tork_governance::GovernanceResult>() {
        println!("Receipt ID: {}", result.receipt.receipt_id);
    }

    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(TorkMiddleware::new().skip_paths(vec!["/health"]))
            .route("/chat", web::post().to(chat))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Axum Layer

```rust
use axum::{
    routing::post,
    Router,
    Extension,
    Json,
};
use tork_governance::middleware::axum::TorkLayer;
use tork_governance::GovernanceResult;

async fn chat(Extension(result): Extension<GovernanceResult>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "receipt_id": result.receipt.receipt_id,
        "status": "ok"
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/chat", post(chat))
        .layer(TorkLayer::new().skip_paths(vec!["/health"]));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Rocket Fairing

```rust
#[macro_use] extern crate rocket;

use rocket::State;
use rocket::request::Request;
use tork_governance::middleware::rocket::TorkFairing;
use tork_governance::GovernanceResult;

#[post("/chat")]
fn chat(result: &State<GovernanceResult>) -> String {
    format!("Receipt ID: {}", result.receipt.receipt_id)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(TorkFairing::new().skip_paths(vec!["/health"]))
        .mount("/", routes![chat])
}
```

## Features

- **PII Detection**: SSN, credit cards, emails, phones, addresses, IP addresses, and more
- **Automatic Redaction**: Replace sensitive data with type-specific placeholders
- **Cryptographic Receipts**: SHA256 hashes for audit trails
- **High Performance**: Compiled regex patterns for microsecond latency
- **Thread Safe**: Can be used across threads with proper synchronization

## API

### `Tork` Struct

```rust
use tork_governance::{Tork, TorkConfig, GovernanceAction};

// Default configuration
let mut tork = Tork::new();

// Custom configuration
let config = TorkConfig {
    policy_version: "2.0.0".to_string(),
    default_action: GovernanceAction::Deny,
};
let mut tork = Tork::with_config(config);

// Apply governance
let result = tork.govern("My SSN is 123-45-6789");

// Get statistics
let stats = tork.get_stats();
println!("Total calls: {}", stats.total_calls);

// Reset statistics
tork.reset_stats();
```

### `detect_pii` Function

```rust
use tork_governance::detect_pii;

let result = detect_pii("Contact: john@example.com");
assert!(result.has_pii);
assert!(result.types.contains(&tork_governance::PIIType::Email));
println!("Redacted: {}", result.redacted_text);
```

### Utility Functions

```rust
use tork_governance::{hash_text, generate_receipt_id};

let hash = hash_text("test");
// "sha256:9f86d08..."

let receipt_id = generate_receipt_id();
// "rcpt_a1b2c3..."
```

## Supported PII Types

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 01/15/1990 | [DOB_REDACTED] |
| Passport | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | D1234567 | [DL_REDACTED] |
| Bank Account | 12345678901234 | [ACCOUNT_REDACTED] |

## Performance

Target latency: <500 microseconds on edge hardware (pending hardware validation).

## License

MIT
