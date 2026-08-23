//! rove-abctl — build, inspect and verify rove-addrbook `.rab` artifacts.
//!
//! The address book is released like software: `fetch` refreshes raw source
//! data from public provider feeds, `build` compiles it into a deterministic
//! binary artifact, `diff` gates a release against the previous one, and
//! `verify`/`inspect`/`query`/`bench` operate on published artifacts.

use anyhow::Context;
use rove::addrbook::sources::{apply_manifest, Manifest};
use rove::addrbook::{control_plane_catalog_json, AddrBook, BookBuilder};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const MAX_FETCH_BYTES: usize = 128 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> anyhow::Result<i32> {
    let Some(cmd) = args.first() else {
        print_usage();
        return Ok(2);
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "build" => cmd_build(rest),
        "inspect" => cmd_inspect(rest),
        "query" => cmd_query(rest),
        "verify" => cmd_verify(rest),
        "diff" => cmd_diff(rest),
        "fetch" => cmd_fetch(rest),
        "bench" => cmd_bench(rest),
        "export" => cmd_export(rest),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(0)
        }
        other => {
            eprintln!("unknown command {other:?}\n");
            print_usage();
            Ok(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "rove-abctl — rove-addrbook artifact toolchain

USAGE:
  rove-abctl build  --manifest <book.toml> --out <book.rab> [--epoch <n>]
  rove-abctl inspect <book.rab> [--categories]
  rove-abctl query  <book.rab> <host-or-ip> [category ...]
  rove-abctl verify <book.rab>
  rove-abctl diff   <old.rab> <new.rab> [--max-shrink <pct>]
  rove-abctl fetch  --manifest <book.toml> [--only <path-substr>]
  rove-abctl bench  <book.rab> [--iterations <n>]
  rove-abctl export <book.rab> --out <rove-addrbook.json>

COMMANDS:
  build    Compile manifest sources into a deterministic .rab artifact.
  inspect  Print artifact metadata (epoch, checksum, entry counts).
  query    Look up which categories match a host/IP; with categories
           given, also report whether that selector matches (exit 0/1).
  verify   Full structural + checksum validation (exit 0 = valid).
  diff     Compare two artifacts; fails if the new one shrank more than
           --max-shrink percent (default 30) — a release anomaly gate.
  fetch    Download sources that declare a url= into their path= files.
  bench    Measure lookup throughput on the artifact.
  export   Full control-plane sidecar JSON (TeamsEdge rove-addrbook.json)."
    );
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn positional(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if let Some(stripped) = a.strip_prefix("--") {
            // Boolean flags take no value; everything else consumes one.
            skip = !matches!(stripped, "categories");
            continue;
        }
        out.push(a.as_str());
    }
    out
}

fn validate_options(args: &[String], value_options: &[&str], flags: &[&str]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if value_options.contains(&arg) {
            if !seen.insert(arg) {
                anyhow::bail!("duplicate option {arg}");
            }
            let value = args
                .get(index + 1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| anyhow::anyhow!("option {arg} requires a value"))?;
            let _ = value;
            index += 2;
            continue;
        }
        if flags.contains(&arg) {
            if !seen.insert(arg) {
                anyhow::bail!("duplicate option {arg}");
            }
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            anyhow::bail!("unknown option {arg:?}");
        }
        index += 1;
    }
    Ok(())
}

fn reject_positionals(args: &[String], command: &str) -> anyhow::Result<()> {
    let extra = positional(args);
    if !extra.is_empty() {
        anyhow::bail!("{command} does not accept positional arguments: {extra:?}");
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("output path must name a file")?
        .to_string_lossy();
    for _ in 0..32 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create temporary output {temp:?} failed"));
            }
        };
        let result = (|| -> anyhow::Result<()> {
            file.write_all(bytes)
                .with_context(|| format!("write temporary output {temp:?} failed"))?;
            file.sync_all()
                .with_context(|| format!("sync temporary output {temp:?} failed"))?;
            drop(file);
            std::fs::rename(&temp, path)
                .with_context(|| format!("publish output {path:?} failed"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        return result;
    }
    anyhow::bail!("could not allocate a unique temporary file for {path:?}");
}

fn cmd_build(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &["--manifest", "--out", "--epoch"], &[])?;
    reject_positionals(args, "build")?;
    let manifest_path = flag_value(args, "--manifest")
        .ok_or_else(|| anyhow::anyhow!("build requires --manifest <book.toml>"))?;
    let out_path = flag_value(args, "--out")
        .ok_or_else(|| anyhow::anyhow!("build requires --out <book.rab>"))?;
    let (manifest, base) = Manifest::load(Path::new(manifest_path))?;
    let epoch = match flag_value(args, "--epoch") {
        Some(v) => v.parse::<u64>().map_err(|e| {
            anyhow::anyhow!("bad --epoch {v:?}: {e} (expected unix seconds or serial)")
        })?,
        None => manifest.epoch,
    };
    let mut builder = BookBuilder::new(epoch);
    let report = apply_manifest(&mut builder, &manifest, &base)?;
    let bytes = builder.build_bytes()?;
    let book = AddrBook::from_bytes(&bytes)?;

    atomic_write(Path::new(out_path), &bytes)?;

    let counts = book.entry_counts();
    println!("built {out_path}");
    println!("  epoch      {}", book.build_epoch());
    println!("  checksum   {}", book.checksum_hex());
    println!("  size       {} bytes", bytes.len());
    println!("  categories {}", book.category_count());
    println!(
        "  entries    catsets={} ip4={} ip6={} exact={} suffix={} keyword={}",
        counts.catsets,
        counts.ip4,
        counts.ip6,
        counts.domain_exact,
        counts.domain_suffix,
        counts.keywords
    );
    for (src, added) in report {
        println!("  source     {src}: {added} entries");
    }
    Ok(0)
}

fn load_book(path: &str) -> anyhow::Result<(AddrBook, usize)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read {path:?}: {e}"))?;
    let len = bytes.len();
    let book = AddrBook::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("load {path:?}: {e}"))?;
    Ok((book, len))
}

fn cmd_inspect(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &[], &["--categories"])?;
    let pos = positional(args);
    let [path] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl inspect <book.rab> [--categories]");
    };
    let (book, size) = load_book(path)?;
    let counts = book.entry_counts();
    println!("artifact   {path}");
    println!("epoch      {}", book.build_epoch());
    println!("checksum   {}", book.checksum_hex());
    println!("size       {size} bytes");
    println!("categories {}", book.category_count());
    println!(
        "entries    catsets={} ip4={} ip6={} exact={} suffix={} keyword={}",
        counts.catsets,
        counts.ip4,
        counts.ip6,
        counts.domain_exact,
        counts.domain_suffix,
        counts.keywords
    );
    if has_flag(args, "--categories") {
        for name in book.categories() {
            println!("category   {name}");
        }
    }
    Ok(0)
}

fn cmd_query(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &[], &[])?;
    let pos = positional(args);
    let [path, host, cats @ ..] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl query <book.rab> <host-or-ip> [category ...]");
    };
    let (book, _) = load_book(path)?;
    let hits = book.lookup_categories(host);
    if hits.is_empty() {
        println!("{host}: no category matches");
    } else {
        println!("{host}: {}", hits.join(", "));
    }
    if cats.is_empty() {
        return Ok(0);
    }
    let patterns: Vec<String> = cats.iter().map(|s| s.to_string()).collect();
    let sel = book.resolve(&patterns)?;
    let matched = book.matches(host, &sel);
    println!(
        "selector [{}] => {}",
        patterns.join(", "),
        if matched { "MATCH" } else { "no match" }
    );
    Ok(if matched { 0 } else { 1 })
}

fn cmd_verify(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &[], &[])?;
    let pos = positional(args);
    let [path] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl verify <book.rab>");
    };
    let (book, size) = load_book(path)?;
    println!(
        "OK {path} (epoch {}, {} categories, {size} bytes, sha256 {})",
        book.build_epoch(),
        book.category_count(),
        book.checksum_hex()
    );
    Ok(0)
}

fn cmd_export(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &["--out"], &[])?;
    let pos = positional(args);
    let [path] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl export <book.rab> --out <rove-addrbook.json>");
    };
    let out_path = flag_value(args, "--out")
        .ok_or_else(|| anyhow::anyhow!("export requires --out <rove-addrbook.json>"))?;
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read {path:?}: {e}"))?;
    let raw = rove::addrbook::format::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("decode {path:?}: {e}"))?;
    let json = control_plane_catalog_json(&raw)?;
    atomic_write(Path::new(out_path), &json)?;
    println!(
        "exported {out_path} (epoch {}, {} categories, {} bytes)",
        raw.build_epoch,
        raw.categories.len(),
        json.len()
    );
    Ok(0)
}

fn cmd_diff(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &["--max-shrink"], &[])?;
    let pos = positional(args);
    let [old_path, new_path] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl diff <old.rab> <new.rab> [--max-shrink <pct>]");
    };
    let max_shrink: f64 = match flag_value(args, "--max-shrink") {
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("bad --max-shrink {v:?}: {e}"))?,
        None => 30.0,
    };
    if !max_shrink.is_finite() || !(0.0..=100.0).contains(&max_shrink) {
        anyhow::bail!("--max-shrink must be a finite percentage in 0..=100");
    }
    let (old, _) = load_book(old_path)?;
    let (new, _) = load_book(new_path)?;

    if old.checksum() == new.checksum() {
        println!("identical artifacts (sha256 {})", old.checksum_hex());
        return Ok(0);
    }

    let old_cats: std::collections::BTreeSet<&str> = old.categories().collect();
    let new_cats: std::collections::BTreeSet<&str> = new.categories().collect();
    let mut anomalies = Vec::new();
    for c in new_cats.difference(&old_cats) {
        println!("+ category {c}");
    }
    for c in old_cats.difference(&new_cats) {
        println!("- category {c}");
        anomalies.push(format!("category {c} was removed"));
    }
    if new.build_epoch() <= old.build_epoch() {
        anomalies.push(format!(
            "build epoch did not increase ({} -> {})",
            old.build_epoch(),
            new.build_epoch()
        ));
    }

    let oc = old.entry_counts();
    let nc = new.entry_counts();
    let pairs = [
        ("catsets", oc.catsets, nc.catsets),
        ("ip4", oc.ip4, nc.ip4),
        ("ip6", oc.ip6, nc.ip6),
        ("domain_exact", oc.domain_exact, nc.domain_exact),
        ("domain_suffix", oc.domain_suffix, nc.domain_suffix),
        ("keyword", oc.keywords, nc.keywords),
    ];
    for (name, o, n) in pairs {
        if o != n {
            println!("  {name}: {o} -> {n}");
        }
        // A dataset that suddenly loses a large share of one section is more
        // likely a broken upstream feed than a real-world change; block the
        // release rather than shipping a book that quietly stopped matching.
        if o > 0 {
            let shrink = (o.saturating_sub(n) as f64) * 100.0 / (o as f64);
            if shrink > max_shrink {
                anomalies.push(format!("{name} shrank {shrink:.1}% ({o} -> {n})"));
            }
        }
    }
    println!(
        "epoch {} -> {}, checksum {} -> {}",
        old.build_epoch(),
        new.build_epoch(),
        old.checksum_hex(),
        new.checksum_hex()
    );
    if !anomalies.is_empty() {
        for a in &anomalies {
            eprintln!("ANOMALY: {a} (limit {max_shrink}%)");
        }
        return Ok(1);
    }
    Ok(0)
}

fn cmd_fetch(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &["--manifest", "--only"], &[])?;
    reject_positionals(args, "fetch")?;
    let manifest_path = flag_value(args, "--manifest")
        .ok_or_else(|| anyhow::anyhow!("fetch requires --manifest <book.toml>"))?;
    let only = flag_value(args, "--only");
    let (manifest, base) = Manifest::load(Path::new(manifest_path))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let mut fetched = 0usize;
    let mut skipped = 0usize;
    for s in &manifest.sources {
        let Some(url) = &s.url else {
            skipped += 1;
            continue;
        };
        if let Some(filter) = only {
            if !s.path.contains(filter) {
                skipped += 1;
                continue;
            }
        }
        let dest = base.join(&s.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = rt.block_on(async {
            let mut resp = client.get(url).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("{url}: HTTP {}", resp.status());
            }
            if resp
                .content_length()
                .is_some_and(|len| len > MAX_FETCH_BYTES as u64)
            {
                anyhow::bail!("{url}: source exceeds {MAX_FETCH_BYTES} byte limit");
            }
            let mut body = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                let next_len = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow::anyhow!("{url}: source size overflow"))?;
                if next_len > MAX_FETCH_BYTES {
                    anyhow::bail!("{url}: source exceeds {MAX_FETCH_BYTES} byte limit");
                }
                body.extend_from_slice(&chunk);
            }
            Ok::<_, anyhow::Error>(body)
        })?;
        atomic_write(&dest, &body)?;
        println!("fetched {} ({} bytes) <- {url}", s.path, body.len());
        fetched += 1;
    }
    println!("fetch done: {fetched} downloaded, {skipped} skipped");
    Ok(0)
}

fn cmd_bench(args: &[String]) -> anyhow::Result<i32> {
    validate_options(args, &["--iterations"], &[])?;
    let pos = positional(args);
    let [path] = pos.as_slice() else {
        anyhow::bail!("usage: rove-abctl bench <book.rab> [--iterations <n>]");
    };
    let iterations: u64 = match flag_value(args, "--iterations") {
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("bad --iterations {v:?}: {e}"))?,
        None => 1_000_000,
    };
    if iterations == 0 {
        anyhow::bail!("--iterations must be greater than zero");
    }
    let (book, _) = load_book(path)?;
    let all: Vec<String> = book.categories().map(str::to_string).collect();
    if all.is_empty() {
        anyhow::bail!("artifact has no categories to bench against");
    }
    let sel = book.resolve(&all)?;

    // Mixed workload: hit + miss domains and IPs exercise every match path.
    let probes = [
        "www.google.com",
        "definitely-not-in-book.example",
        "a.b.c.d.e.long-chain.test",
        "8.8.8.8",
        "203.0.113.7",
        "2001:4860:4860::8888",
    ];
    let mut hits = 0u64;
    let start = Instant::now();
    for i in 0..iterations {
        let probe = probes[(i % probes.len() as u64) as usize];
        if book.matches(probe, &sel) {
            hits += 1;
        }
    }
    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() as f64 / iterations as f64;
    println!(
        "{iterations} lookups in {:.3}s — {per_op:.0} ns/lookup ({:.2}M lookups/s), {hits} hits",
        elapsed.as_secs_f64(),
        1000.0 / per_op
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn diff_rejects_invalid_shrink_thresholds_before_reading_files() {
        for value in ["-1", "101", "NaN", "inf"] {
            let err = cmd_diff(&args(&["old.rab", "new.rab", "--max-shrink", value]))
                .expect_err("invalid threshold must fail");
            assert!(err.to_string().contains("finite percentage"), "{err}");
        }
    }

    #[test]
    fn commands_reject_unknown_duplicate_and_missing_options() {
        for values in [
            &["old.rab", "new.rab", "--max-shrik", "5"][..],
            &["old.rab", "new.rab", "--max-shrink"][..],
            &[
                "old.rab",
                "new.rab",
                "--max-shrink",
                "5",
                "--max-shrink",
                "6",
            ][..],
        ] {
            assert!(cmd_diff(&args(values)).is_err(), "{values:?}");
        }
        assert!(cmd_build(&args(&[
            "--manifest",
            "book.toml",
            "--out",
            "book.rab",
            "unexpected"
        ]))
        .is_err());
    }

    #[test]
    fn bench_rejects_zero_iterations_before_reading_artifact() {
        let err = cmd_bench(&args(&["missing.rab", "--iterations", "0"]))
            .expect_err("zero iterations must fail");
        assert!(err.to_string().contains("greater than zero"), "{err}");
    }

    #[test]
    fn concurrent_atomic_writes_publish_only_complete_values() {
        let dir = std::env::temp_dir().join(format!(
            "rove-abctl-write-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("book.rab");
        let a = vec![0xAA; 64 * 1024];
        let b = vec![0x55; 96 * 1024];
        let path_a = path.clone();
        let path_b = path.clone();
        let a_for_write = a.clone();
        let b_for_write = b.clone();
        let first = std::thread::spawn(move || atomic_write(&path_a, &a_for_write).unwrap());
        let second = std::thread::spawn(move || atomic_write(&path_b, &b_for_write).unwrap());
        first.join().unwrap();
        second.join().unwrap();

        let published = std::fs::read(&path).unwrap();
        assert!(published == a || published == b);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn diff_blocks_category_removal_and_nonincreasing_epoch() {
        let dir = std::env::temp_dir().join(format!(
            "rove-abctl-diff-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let old_path = dir.join("old.rab");
        let new_path = dir.join("new.rab");

        let mut old = BookBuilder::new(10);
        old.add_rule("kept", "kept.example").unwrap();
        old.add_rule("removed", "removed.example").unwrap();
        atomic_write(&old_path, &old.build_bytes().unwrap()).unwrap();
        let mut new = BookBuilder::new(10);
        new.add_rule("kept", "changed.example").unwrap();
        atomic_write(&new_path, &new.build_bytes().unwrap()).unwrap();

        let code = cmd_diff(&args(&[
            old_path.to_str().unwrap(),
            new_path.to_str().unwrap(),
            "--max-shrink",
            "100",
        ]))
        .unwrap();
        assert_eq!(code, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn diff_applies_shrink_gate_to_catsets() {
        let dir = std::env::temp_dir().join(format!(
            "rove-abctl-catsets-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let old_path = dir.join("old.rab");
        let new_path = dir.join("new.rab");

        let mut old = BookBuilder::new(10);
        old.add_rule("a", "one.example").unwrap();
        old.add_rule("b", "two.example").unwrap();
        old.add_rule("a", "both.example").unwrap();
        old.add_rule("b", "both.example").unwrap();
        atomic_write(&old_path, &old.build_bytes().unwrap()).unwrap();

        let mut new = BookBuilder::new(11);
        new.add_rule("a", "one.example").unwrap();
        new.add_rule("b", "two.example").unwrap();
        new.add_rule("a", "both.example").unwrap();
        atomic_write(&new_path, &new.build_bytes().unwrap()).unwrap();

        let old_book = load_book(old_path.to_str().unwrap()).unwrap().0;
        let new_book = load_book(new_path.to_str().unwrap()).unwrap().0;
        assert_eq!(old_book.entry_counts().catsets, 3);
        assert_eq!(new_book.entry_counts().catsets, 2);
        let code = cmd_diff(&args(&[
            old_path.to_str().unwrap(),
            new_path.to_str().unwrap(),
            "--max-shrink",
            "30",
        ]))
        .unwrap();
        assert_eq!(code, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
