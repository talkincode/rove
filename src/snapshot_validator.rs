use crate::addrbook::AddrBookService;
use crate::model::{decode_snapshot, Snapshot};
use serde::Serialize;
use std::io::{Read, Write};

pub const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

const HELP: &str = "\
Usage: rove validate-snapshot --node-id <id> [--addrbook <book.rab>] [<snapshot.json>|-]

Validates a snapshot through the same decode and compile path used by an Rove node.
The input defaults to stdin. Results are emitted as one JSON object on stdout.
";

#[derive(Debug, PartialEq, Eq)]
struct ValidatorArgs {
    node_id: String,
    addrbook: Option<String>,
    input: String,
}

enum ParseResult {
    Run(ValidatorArgs),
    Help,
}

#[derive(Serialize)]
struct SuccessOutput {
    ok: bool,
    schema_version: u32,
    version: u64,
    users: usize,
    routing_policies: usize,
    egresses: usize,
}

#[derive(Serialize)]
struct FailureOutput<'a> {
    ok: bool,
    stage: &'a str,
    error: &'a str,
}

/// Run the one-shot public validator. The returned value is the intended
/// process exit code. Expected validation failures are written only as JSON to
/// `stdout`; input data and compiler details are deliberately not echoed.
pub fn run_cli<I, S, R, W>(args: I, mut stdin: R, mut stdout: W) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    R: Read,
    W: Write,
{
    let args = match parse_args(args) {
        Ok(ParseResult::Run(args)) => args,
        Ok(ParseResult::Help) => {
            return if stdout.write_all(HELP.as_bytes()).is_ok() {
                0
            } else {
                1
            };
        }
        Err(message) => return write_failure(&mut stdout, "arguments", message),
    };

    let bytes = match read_input(&args.input, &mut stdin) {
        Ok(bytes) => bytes,
        Err(ReadFailure::TooLarge) => {
            return write_failure(
                &mut stdout,
                "read",
                "snapshot input exceeds the maximum size",
            );
        }
        Err(ReadFailure::Io) => {
            return write_failure(&mut stdout, "read", "failed to read snapshot input");
        }
    };

    let book_service = match args.addrbook.as_deref() {
        Some(path) => match AddrBookService::load(path) {
            Ok(service) => Some(service),
            Err(_) => {
                return write_failure(&mut stdout, "addrbook", "failed to load addrbook");
            }
        },
        None => None,
    };
    let book = book_service.as_ref().map(|service| service.current());

    let document = match decode_snapshot(&bytes) {
        Ok(document) => document,
        Err(_) => {
            return write_failure(&mut stdout, "decode", "snapshot decode failed");
        }
    };
    let routing_policies = document.routing_policy_count();
    let egresses = document.egress_definition_count();
    let snapshot = match Snapshot::compile_with_book(document, &args.node_id, book.as_ref()) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return write_failure(&mut stdout, "compile", "snapshot compile failed");
        }
    };

    write_json(
        &mut stdout,
        &SuccessOutput {
            ok: true,
            schema_version: snapshot.schema_version,
            version: snapshot.version,
            users: snapshot.user_count(),
            routing_policies,
            egresses,
        },
        0,
    )
}

fn parse_args<I, S>(args: I) -> Result<ParseResult, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(ParseResult::Help);
    }

    let mut node_id = None;
    let mut addrbook = None;
    let mut input = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--node-id" => {
                index += 1;
                let value = args.get(index).ok_or("--node-id requires a value")?;
                if node_id.replace(value.clone()).is_some() {
                    return Err("--node-id may only be specified once");
                }
            }
            "--addrbook" => {
                index += 1;
                let value = args.get(index).ok_or("--addrbook requires a value")?;
                if addrbook.replace(value.clone()).is_some() {
                    return Err("--addrbook may only be specified once");
                }
            }
            "-" => {
                if input.replace("-".to_string()).is_some() {
                    return Err("only one snapshot input may be specified");
                }
            }
            value if value.starts_with('-') => return Err("unknown validator argument"),
            value => {
                if input.replace(value.to_string()).is_some() {
                    return Err("only one snapshot input may be specified");
                }
            }
        }
        index += 1;
    }

    let node_id = node_id.ok_or("--node-id is required")?;
    if node_id.trim().is_empty() {
        return Err("--node-id must not be empty");
    }
    if addrbook.as_ref().is_some_and(|path| path.trim().is_empty()) {
        return Err("--addrbook must not be empty");
    }
    Ok(ParseResult::Run(ValidatorArgs {
        node_id,
        addrbook,
        input: input.unwrap_or_else(|| "-".to_string()),
    }))
}

enum ReadFailure {
    TooLarge,
    Io,
}

fn read_input(input: &str, stdin: &mut impl Read) -> Result<Vec<u8>, ReadFailure> {
    if input == "-" {
        return read_limited(stdin);
    }
    let file = std::fs::File::open(input).map_err(|_| ReadFailure::Io)?;
    if file.metadata().map_err(|_| ReadFailure::Io)?.len() > MAX_SNAPSHOT_BYTES as u64 {
        return Err(ReadFailure::TooLarge);
    }
    read_limited(file)
}

fn read_limited(mut reader: impl Read) -> Result<Vec<u8>, ReadFailure> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Io)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(ReadFailure::TooLarge);
    }
    Ok(bytes)
}

fn write_failure(stdout: &mut impl Write, stage: &str, error: &str) -> u8 {
    write_json(
        stdout,
        &FailureOutput {
            ok: false,
            stage,
            error,
        },
        1,
    )
}

fn write_json(stdout: &mut impl Write, value: &impl Serialize, exit_code: u8) -> u8 {
    if serde_json::to_writer(&mut *stdout, value).is_err() || stdout.write_all(b"\n").is_err() {
        return 1;
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_node_and_defaults_to_stdin() {
        assert!(parse_args(Vec::<String>::new()).is_err());
        let ParseResult::Run(args) = parse_args(["--node-id", "edge-1"]).unwrap() else {
            panic!("expected validator args");
        };
        assert_eq!(args.node_id, "edge-1");
        assert_eq!(args.input, "-");
    }

    #[test]
    fn limited_reader_rejects_oversized_input() {
        let bytes = vec![b'x'; MAX_SNAPSHOT_BYTES + 1];
        assert!(matches!(
            read_limited(bytes.as_slice()),
            Err(ReadFailure::TooLarge)
        ));
    }
}
