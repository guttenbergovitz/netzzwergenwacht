//! Model Context Protocol (MCP) JSON-RPC 2.0 `stdio` server.
//!
//! Exposes deterministic `NetzZwergenWacht` validation, single-URL audit, and
//! bounded site-scan tools over line-delimited JSON-RPC on `stdin`/`stdout`.

use std::io::{BufRead as _, Write as _};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::analysis::assessment::{assess_crawl_summary, assess_from_analysers};
use crate::discovery::CrawlBudget;
use crate::domain::{AuditTarget, CollectorOutcome, ExecutionBudget, TargetPolicy};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// Runs the blocking line-delimited MCP `stdio` loop until EOF.
///
/// # Errors
///
/// Returns an `io::Error` if reading from `stdin` or writing to `stdout` fails.
pub async fn run_stdio_server() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(reply) = handle_mcp_request_line(trimmed).await {
            stdout.write_all(reply.as_bytes())?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// Processes a single JSON-RPC 2.0 request line and returns an optional serialised response.
pub async fn handle_mcp_request_line(line: &str) -> Option<String> {
    let req: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(req) => req,
        Err(err) => {
            return serde_json::to_string(&JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: format!("Parse error: {err}"),
                }),
            })
            .ok();
        }
    };

    // Notifications omit `id` and expect no reply.
    let id = req.id?;

    let response = match req.method.as_str() {
        "initialize" => ok_response(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "netzzwergenwacht",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),
        "ping" => ok_response(id, json!({})),
        "tools/list" => ok_response(id, json!({ "tools": mcp_tool_definitions() })),
        "tools/call" => handle_tool_call(id, &req.params).await,
        other => err_response(id, -32601, format!("Method not found: {other}")),
    };
    serde_json::to_string(&response).ok()
}

fn ok_response(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn err_response(id: Value, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}

fn mcp_tool_definitions() -> Value {
    json!([
        {
            "name": "nzw_validate_url",
            "description": "Validate a target URL against NetzZwergenWacht SSRF and target policies without performing network I/O.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "allow_private": { "type": "boolean", "default": false }
                },
                "required": ["url"]
            }
        },
        {
            "name": "nzw_audit_url",
            "description": "Run a bounded deterministic audit on a single URL and return prioritised LLM fix prompts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "allow_private": { "type": "boolean", "default": false }
                },
                "required": ["url"]
            }
        },
        {
            "name": "nzw_scan_site",
            "description": "Run a bounded same-origin site scan and return grouped fix prompts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "max_pages": { "type": "integer", "default": 10 },
                    "max_depth": { "type": "integer", "default": 2 },
                    "allow_private": { "type": "boolean", "default": false }
                },
                "required": ["url"]
            }
        }
    ])
}

fn tool_error_response(id: Value, message: &str) -> JsonRpcResponse {
    ok_response(
        id,
        json!({
            "isError": true,
            "content": [{ "type": "text", "text": message }]
        }),
    )
}

async fn handle_tool_call(id: Value, params: &Value) -> JsonRpcResponse {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return err_response(id, -32602, "Missing tool `name`".to_owned());
    };
    let args = params.get("arguments").unwrap_or(&Value::Null);
    let allow_private = args
        .get("allow_private")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let policy = if allow_private {
        TargetPolicy::AllowPrivate
    } else {
        TargetPolicy::PublicOnly
    };
    let Some(raw_url) = args.get("url").and_then(Value::as_str) else {
        return err_response(id, -32602, "Missing required argument `url`".to_owned());
    };

    let target = match AuditTarget::parse(raw_url, policy) {
        Ok(t) => t,
        Err(err) => return tool_error_response(id, &format!("invalid target: {err}")),
    };

    match name {
        "nzw_validate_url" => ok_response(
            id,
            json!({
                "content": [{ "type": "text", "text": format!("valid: {}", target.as_str()) }]
            }),
        ),
        "nzw_audit_url" => {
            let snap =
                crate::collection::collect_http(&target, &ExecutionBudget::default(), policy).await;
            let report = crate::analysis::run_all(&snap);
            let http_ok = matches!(
                report.http,
                CollectorOutcome::Captured { .. } | CollectorOutcome::Partial { .. }
            );
            let assessment = assess_from_analysers(&report.analysers, http_ok, Vec::new());
            let text = crate::report_llm::render_audit_llm(&report, &assessment);
            ok_response(id, json!({ "content": [{ "type": "text", "text": text }] }))
        }
        "nzw_scan_site" => {
            let max_pages = args
                .get("max_pages")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(10)
                .clamp(1, 50);
            let max_depth = args
                .get("max_depth")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(2)
                .min(4);
            let exec_budget = ExecutionBudget::default();
            let crawl_budget = CrawlBudget {
                max_pages,
                max_depth,
                max_duration: exec_budget.audit_timeout,
            };
            let summary = crate::discovery::crawl_and_cluster(
                target.clone(),
                crawl_budget,
                exec_budget,
                policy,
            )
            .await;
            let assessment = assess_crawl_summary(&summary);
            let text = crate::report_llm::render_scan_llm(target.as_str(), &summary, &assessment);
            ok_response(id, json!({ "content": [{ "type": "text", "text": text }] }))
        }
        other => err_response(id, -32601, format!("Unknown tool: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mcp_server_handles_initialize_tools_list_and_validate_call() {
        let init = handle_mcp_request_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .await
        .expect("init reply");
        assert!(init.contains("protocolVersion"));
        assert!(init.contains("netzzwergenwacht"));

        let list = handle_mcp_request_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )
        .await
        .expect("tools/list reply");
        assert!(list.contains("nzw_validate_url"));
        assert!(list.contains("nzw_audit_url"));
        assert!(list.contains("nzw_scan_site"));

        let call = handle_mcp_request_line(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nzw_validate_url","arguments":{"url":"https://example.com/"}}}"#,
        )
        .await
        .expect("tools/call reply");
        assert!(call.contains("valid: https://example.com/"));

        let notif = handle_mcp_request_line(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        )
        .await;
        assert!(notif.is_none());
    }
}
