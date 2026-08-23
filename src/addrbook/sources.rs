//! Source manifest and collectors for `rove-abctl build` / `fetch`: turn public
//! provider publications and curated lists into builder entries.
//!
//! Supported source kinds:
//! * `cidrs` — text, one IP or CIDR per line, `#` comments.
//! * `domains` — text in Rove rule syntax (bare suffix, `full:`, `domain:`,
//!   `keyword:`), `#` comments.
//! * `v2fly-domains` — a `domain-list-community` data file: confined recursive
//!   `include:`, selective `@attr` / `@-attr` filters, attributes and
//!   affiliations are resolved; `regexp:` is skipped (the matcher is regex-free).
//! * `aws-ip-ranges` — the official `ip-ranges.json`; entries are filed under
//!   `<category>` and `<category>/<service>` (lowercased).
//! * `azure-service-tags` — the official `ServiceTags_Public.json`; entries
//!   are filed under `<category>` and `<category>/<systemService|name>`.
//! * `gcp-cloud-json` — the official `goog.json` / `cloud.json`; entries are
//!   filed under `<category>` and, when present, `<category>/<service>`.

use super::builder::BookBuilder;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_V2FLY_EXPANSION_WORK: usize = 1_000_000;
const MAX_V2FLY_METADATA_ITEMS: usize = 64;

pub const KINDS: &[&str] = &[
    "cidrs",
    "domains",
    "v2fly-domains",
    "aws-ip-ranges",
    "azure-service-tags",
    "gcp-cloud-json",
];

#[derive(Debug, Deserialize)]
pub struct Manifest {
    /// Build epoch stamped into the artifact (overridable via `--epoch`).
    #[serde(default)]
    pub epoch: u64,
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
}

#[derive(Debug, Deserialize)]
pub struct Source {
    pub category: String,
    pub kind: String,
    /// Path to the local data file, relative to the manifest's directory.
    pub path: String,
    /// Optional upstream URL used by `rove-abctl fetch` to refresh `path`.
    #[serde(default)]
    pub url: Option<String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<(Manifest, PathBuf)> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read manifest {path:?} failed"))?;
        let manifest: Manifest =
            toml::from_str(&text).with_context(|| format!("parse manifest {path:?}"))?;
        if manifest.sources.is_empty() {
            bail!("manifest {path:?} declares no [[source]] entries");
        }
        for s in &manifest.sources {
            if !KINDS.contains(&s.kind.as_str()) {
                bail!(
                    "manifest {path:?}: unknown source kind {:?} (known: {})",
                    s.kind,
                    KINDS.join(", ")
                );
            }
        }
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok((manifest, base))
    }
}

/// Feed every manifest source into the builder. Returns per-source entry
/// counts for the build report.
pub fn apply_manifest(
    builder: &mut BookBuilder,
    manifest: &Manifest,
    base: &Path,
) -> Result<Vec<(String, usize)>> {
    let mut report = Vec::new();
    for s in &manifest.sources {
        let file = base.join(&s.path);
        let added = apply_source(builder, s, &file)
            .with_context(|| format!("source {:?} ({})", s.path, s.kind))?;
        if added == 0 {
            bail!(
                "source {:?} ({}) produced no supported entries",
                s.path,
                s.kind
            );
        }
        report.push((format!("{} ({})", s.path, s.kind), added));
    }
    Ok(report)
}

fn apply_source(builder: &mut BookBuilder, source: &Source, file: &Path) -> Result<usize> {
    match source.kind.as_str() {
        "cidrs" => apply_cidrs(builder, &source.category, file),
        "domains" => apply_domains(builder, &source.category, file),
        "v2fly-domains" => apply_v2fly(builder, &source.category, file),
        "aws-ip-ranges" => apply_aws(builder, &source.category, file),
        "azure-service-tags" => apply_azure(builder, &source.category, file),
        "gcp-cloud-json" => apply_gcp(builder, &source.category, file),
        other => bail!("unknown source kind {other:?}"),
    }
}

fn read_lines(file: &Path) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read source {file:?} failed"))?;
    Ok(text
        .lines()
        .map(|l| {
            // Strip trailing comments and whitespace.
            let l = l.split('#').next().unwrap_or("");
            l.trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect())
}

fn apply_cidrs(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let mut n = 0;
    for line in read_lines(file)? {
        add_ip_rule(builder, category, &line, file)?;
        n += 1;
    }
    Ok(n)
}

fn add_ip_rule(builder: &mut BookBuilder, category: &str, prefix: &str, file: &Path) -> Result<()> {
    if super::builder::parse_ip_entries(prefix).is_none() {
        bail!("{file:?}: {prefix:?} is not a valid IP or CIDR");
    }
    builder.add_rule(category, prefix)
}

fn add_provider_cidr(
    builder: &mut BookBuilder,
    category: &str,
    prefix: &str,
    file: &Path,
) -> Result<()> {
    if !prefix.contains('/') {
        bail!("{file:?}: provider prefix {prefix:?} must be a CIDR");
    }
    let network: ipnet::IpNet = prefix
        .parse()
        .with_context(|| format!("{file:?}: invalid provider CIDR {prefix:?}"))?;
    let canonical = match network {
        ipnet::IpNet::V4(network) => network.addr() == network.network(),
        ipnet::IpNet::V6(network) => network.addr() == network.network(),
    };
    if !canonical {
        bail!("{file:?}: provider CIDR {prefix:?} has host bits set");
    }
    builder.add_rule(category, prefix)
}

fn apply_domains(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let mut n = 0;
    for line in read_lines(file)? {
        builder.add_rule(category, &line)?;
        n += 1;
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct V2Rule {
    rule: String,
    attrs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct V2Collection {
    rules: BTreeSet<V2Rule>,
    affiliations: BTreeSet<(String, V2Rule)>,
}

#[derive(Debug)]
enum AttrFilter {
    With(String),
    Without(String),
}

impl AttrFilter {
    fn matches(&self, rule: &V2Rule) -> bool {
        match self {
            AttrFilter::With(attr) => rule.attrs.iter().any(|candidate| candidate == attr),
            AttrFilter::Without(attr) => !rule.attrs.iter().any(|candidate| candidate == attr),
        }
    }
}

/// v2fly `domain-list-community` data file. Includes are confined to the
/// initial file's directory (including through symlinks), recursively resolved,
/// and support the official `@attr` / `@-attr` selective-include semantics.
/// `regexp:` lines are deliberately skipped because the matcher is regex-free.
fn apply_v2fly(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let root = std::fs::canonicalize(file.parent().unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("resolve v2fly source root for {file:?}"))?;
    let selected_extension = file.extension();
    let mut sibling_files = Vec::new();
    for entry in
        std::fs::read_dir(&root).with_context(|| format!("list v2fly source root {root:?}"))?
    {
        let entry = entry.with_context(|| format!("read v2fly source root entry {root:?}"))?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.'))
            || path.extension() != selected_extension
            || !std::fs::metadata(&path)
                .with_context(|| format!("stat v2fly sibling {path:?}"))?
                .is_file()
        {
            continue;
        }
        sibling_files.push(path);
    }
    sibling_files.sort();

    let mut work = 0usize;
    let mut global_affiliations: HashMap<String, BTreeSet<V2Rule>> = HashMap::new();
    for sibling in &sibling_files {
        for (target, rule) in collect_direct_v2fly_affiliations(sibling, &root, &mut work)? {
            global_affiliations.entry(target).or_default().insert(rule);
        }
    }

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let collection = collect_v2fly(
        file,
        &root,
        0,
        &global_affiliations,
        &mut cache,
        &mut visiting,
        &mut work,
    )?;

    let mut categorized: BTreeSet<(String, V2Rule)> = collection
        .rules
        .iter()
        .cloned()
        .map(|rule| (category.to_string(), rule))
        .collect();
    let namespace = category.rsplit_once('/').map(|(namespace, _)| namespace);
    let affiliated_target = |affiliation: &str| match namespace {
        Some(namespace) => format!("{namespace}/{affiliation}"),
        None => affiliation.to_string(),
    };
    for (affiliation, entry) in &collection.affiliations {
        categorized.insert((affiliated_target(affiliation), entry.clone()));
    }
    for (affiliation, rules) in &global_affiliations {
        let target = affiliated_target(affiliation);
        for rule in rules {
            categorized.insert((target.clone(), rule.clone()));
        }
    }
    let output_work = categorized.iter().try_fold(0usize, |total, (_, rule)| {
        total.checked_add(1 + rule.attrs.len())
    });
    charge_v2fly_work(
        &mut work,
        output_work.context("v2fly output expansion size overflow")?,
        file,
    )?;
    for (target, entry) in categorized {
        add_v2_rule(builder, &target, &entry)?;
    }
    Ok(collection.rules.len())
}

fn add_v2_rule(builder: &mut BookBuilder, category: &str, entry: &V2Rule) -> Result<()> {
    builder.add_rule(category, &entry.rule)?;
    for attr in &entry.attrs {
        builder.add_rule(&format!("{category}@{attr}"), &entry.rule)?;
    }
    Ok(())
}

fn collect_v2fly(
    file: &Path,
    root: &Path,
    depth: usize,
    global_affiliations: &HashMap<String, BTreeSet<V2Rule>>,
    cache: &mut HashMap<PathBuf, V2Collection>,
    visiting: &mut HashSet<PathBuf>,
    work: &mut usize,
) -> Result<V2Collection> {
    if depth > 16 {
        bail!("v2fly include chain too deep at {file:?}");
    }
    let file = std::fs::canonicalize(file)
        .with_context(|| format!("resolve v2fly source path {file:?}"))?;
    if !file.starts_with(root) {
        bail!("v2fly include escapes source root: {file:?}");
    }
    if let Some(cached) = cache.get(&file) {
        return Ok(cached.clone());
    }
    if !visiting.insert(file.clone()) {
        bail!("v2fly include cycle detected at {file:?}");
    }

    let result = (|| -> Result<V2Collection> {
        let dir = file.parent().unwrap_or(root);
        let mut out = V2Collection::default();
        if let Some(name) = file.file_name().and_then(|name| name.to_str()) {
            if let Some(rules) = global_affiliations.get(name) {
                charge_v2fly_work(work, rules.len(), &file)?;
                out.rules.extend(rules.iter().cloned());
            }
        }
        for line in read_lines(&file)? {
            charge_v2fly_work(work, 1, &file)?;
            let mut parts = line.split_whitespace();
            let entry = parts.next().unwrap_or("");
            if entry.is_empty() {
                continue;
            }
            if let Some(included) = entry.strip_prefix("include:") {
                validate_include_path(included, &file)?;
                let mut filters = Vec::new();
                for token in parts {
                    let Some(attr) = token.strip_prefix('@') else {
                        bail!("{file:?}: invalid include filter {token:?}");
                    };
                    if attr.is_empty() || attr == "-" {
                        bail!("{file:?}: empty include attribute filter");
                    }
                    match attr.strip_prefix('-') {
                        Some(negative) => filters.push(AttrFilter::Without(negative.to_string())),
                        None => filters.push(AttrFilter::With(attr.to_string())),
                    }
                    if filters.len() > MAX_V2FLY_METADATA_ITEMS {
                        bail!(
                            "{file:?}: include has more than \
                             {MAX_V2FLY_METADATA_ITEMS} attribute filters"
                        );
                    }
                }
                let included_rules = collect_v2fly(
                    &dir.join(included),
                    root,
                    depth + 1,
                    global_affiliations,
                    cache,
                    visiting,
                    work,
                )?;
                charge_v2fly_work(
                    work,
                    included_rules.rules.len() + included_rules.affiliations.len(),
                    &file,
                )?;
                let attribute_slots = included_rules
                    .rules
                    .iter()
                    .try_fold(0usize, |total, rule| {
                        total.checked_add(rule.attrs.len().max(1))
                    })
                    .context("v2fly filter attribute count overflow")?;
                let filter_work = attribute_slots
                    .checked_mul(filters.len())
                    .context("v2fly filter work overflow")?;
                charge_v2fly_work(work, filter_work, &file)?;
                out.affiliations.extend(included_rules.affiliations);
                out.rules.extend(
                    included_rules
                        .rules
                        .into_iter()
                        .filter(|rule| filters.iter().all(|filter| filter.matches(rule))),
                );
                continue;
            }
            let metadata: Vec<&str> = parts.collect();
            let Some((rule, affiliations)) = parse_v2fly_domain_rule(entry, &metadata, &file)?
            else {
                continue;
            };
            for affiliation in affiliations {
                out.affiliations.insert((affiliation, rule.clone()));
            }
            out.rules.insert(rule);
        }
        Ok(out)
    })();
    visiting.remove(&file);
    if let Ok(collection) = &result {
        cache.insert(file, collection.clone());
    }
    result
}

fn collect_direct_v2fly_affiliations(
    file: &Path,
    root: &Path,
    work: &mut usize,
) -> Result<BTreeSet<(String, V2Rule)>> {
    let file = std::fs::canonicalize(file)
        .with_context(|| format!("resolve v2fly affiliation source {file:?}"))?;
    if !file.starts_with(root) {
        bail!("v2fly affiliation source escapes root: {file:?}");
    }
    let mut affiliations = BTreeSet::new();
    for line in read_lines(&file)? {
        charge_v2fly_work(work, 1, &file)?;
        let mut parts = line.split_whitespace();
        let entry = parts.next().unwrap_or("");
        if entry.is_empty() || entry.starts_with("include:") || entry.starts_with("regexp:") {
            continue;
        }
        let metadata: Vec<&str> = parts.collect();
        if !metadata.iter().any(|token| token.starts_with('&')) {
            continue;
        }
        let Some((rule, targets)) = parse_v2fly_domain_rule(entry, &metadata, &file)? else {
            continue;
        };
        for target in targets {
            affiliations.insert((target, rule.clone()));
        }
    }
    Ok(affiliations)
}

fn parse_v2fly_domain_rule(
    entry: &str,
    metadata: &[&str],
    file: &Path,
) -> Result<Option<(V2Rule, Vec<String>)>> {
    if entry.starts_with("regexp:") {
        return Ok(None);
    }
    if metadata.len() > MAX_V2FLY_METADATA_ITEMS {
        bail!(
            "{file:?}: domain rule has more than \
             {MAX_V2FLY_METADATA_ITEMS} metadata items"
        );
    }
    let mut attrs = Vec::new();
    let mut affiliations = Vec::new();
    for token in metadata {
        if let Some(attr) = token.strip_prefix('@') {
            if attr.is_empty() {
                bail!("{file:?}: empty domain attribute");
            }
            attrs.push(attr.to_string());
        } else if let Some(target) = token.strip_prefix('&') {
            if target.is_empty() {
                bail!("{file:?}: empty domain affiliation");
            }
            affiliations.push(target.to_string());
        } else {
            bail!("{file:?}: invalid domain metadata token {token:?}");
        }
    }
    attrs.sort();
    attrs.dedup();
    affiliations.sort();
    affiliations.dedup();
    let rule = match entry.split_once(':') {
        Some(("full", host)) => format!("full:{host}"),
        Some(("domain", host)) => format!("domain:{host}"),
        Some(("keyword", fragment)) => format!("keyword:{fragment}"),
        Some((other, _)) => bail!("{file:?}: unknown v2fly prefix {other:?}"),
        None => format!("domain:{entry}"),
    };
    Ok(Some((V2Rule { rule, attrs }, affiliations)))
}

fn charge_v2fly_work(work: &mut usize, amount: usize, file: &Path) -> Result<()> {
    *work = work
        .checked_add(amount)
        .context("v2fly expansion work overflow")?;
    if *work > MAX_V2FLY_EXPANSION_WORK {
        bail!("v2fly expansion exceeds {MAX_V2FLY_EXPANSION_WORK} operations at {file:?}");
    }
    Ok(())
}

fn validate_include_path(included: &str, file: &Path) -> Result<()> {
    let path = Path::new(included);
    if included.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        bail!("{file:?}: invalid v2fly include path {included:?}");
    }
    Ok(())
}

/// Lowercase a provider service label into a category segment.
fn service_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.@".contains(c) {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

#[derive(Deserialize)]
struct AwsRanges {
    prefixes: Vec<AwsPrefix>,
    ipv6_prefixes: Vec<AwsPrefix6>,
}
#[derive(Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
    service: String,
}
#[derive(Deserialize)]
struct AwsPrefix6 {
    ipv6_prefix: String,
    service: String,
}

fn apply_aws(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read source {file:?} failed"))?;
    let ranges: AwsRanges =
        serde_json::from_str(&text).with_context(|| format!("parse aws ip-ranges {file:?}"))?;
    let mut n = 0;
    for (prefix, service) in ranges
        .prefixes
        .iter()
        .map(|p| (p.ip_prefix.as_str(), p.service.as_str()))
        .chain(
            ranges
                .ipv6_prefixes
                .iter()
                .map(|p| (p.ipv6_prefix.as_str(), p.service.as_str())),
        )
    {
        add_provider_cidr(builder, category, prefix, file)?;
        let seg = service_segment(service);
        if !seg.is_empty() {
            add_provider_cidr(builder, &format!("{category}/{seg}"), prefix, file)?;
        }
        n += 1;
    }
    Ok(n)
}

#[derive(Deserialize)]
struct AzureTags {
    #[serde(default)]
    values: Vec<AzureTag>,
}
#[derive(Deserialize)]
struct AzureTag {
    name: String,
    properties: AzureProps,
}
#[derive(Deserialize)]
struct AzureProps {
    #[serde(rename = "addressPrefixes")]
    address_prefixes: Vec<String>,
    #[serde(default, rename = "systemService")]
    system_service: String,
}

fn apply_azure(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read source {file:?} failed"))?;
    let tags: AzureTags = serde_json::from_str(&text)
        .with_context(|| format!("parse azure service tags {file:?}"))?;
    let mut n = 0;
    for tag in &tags.values {
        let service = if tag.properties.system_service.is_empty() {
            tag.name.split('.').next().unwrap_or("")
        } else {
            tag.properties.system_service.as_str()
        };
        let seg = service_segment(service);
        for prefix in &tag.properties.address_prefixes {
            add_provider_cidr(builder, category, prefix, file)?;
            if !seg.is_empty() {
                add_provider_cidr(builder, &format!("{category}/{seg}"), prefix, file)?;
            }
            n += 1;
        }
    }
    Ok(n)
}

#[derive(Deserialize)]
struct GcpRanges {
    #[serde(default)]
    prefixes: Vec<GcpPrefix>,
}
#[derive(Deserialize)]
struct GcpPrefix {
    #[serde(default, rename = "ipv4Prefix")]
    ipv4: Option<String>,
    #[serde(default, rename = "ipv6Prefix")]
    ipv6: Option<String>,
    #[serde(default)]
    service: Option<String>,
}

fn apply_gcp(builder: &mut BookBuilder, category: &str, file: &Path) -> Result<usize> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read source {file:?} failed"))?;
    let ranges: GcpRanges =
        serde_json::from_str(&text).with_context(|| format!("parse gcp ranges {file:?}"))?;
    let mut n = 0;
    for p in &ranges.prefixes {
        let prefix = match (p.ipv4.as_deref(), p.ipv6.as_deref()) {
            (Some(prefix), None) | (None, Some(prefix)) => prefix,
            (None, None) => bail!("{file:?}: GCP prefix entry has no IPv4 or IPv6 CIDR"),
            (Some(_), Some(_)) => {
                bail!("{file:?}: GCP prefix entry declares both IPv4 and IPv6")
            }
        };
        add_provider_cidr(builder, category, prefix, file)?;
        if let Some(service) = p.service.as_deref() {
            let seg = service_segment(service);
            if !seg.is_empty() {
                add_provider_cidr(builder, &format!("{category}/{seg}"), prefix, file)?;
            }
        }
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::super::book::AddrBook;
    use super::*;

    fn tmpdir() -> tempfile_like::TempDir {
        tempfile_like::TempDir::new("rove-addrbook-sources")
    }

    /// Minimal self-cleaning temp dir so these tests need no new dev-deps.
    mod tempfile_like {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir(PathBuf);
        impl TempDir {
            pub fn new(prefix: &str) -> Self {
                for _ in 0..100 {
                    let unique = format!(
                        "{prefix}-{}-{}",
                        std::process::id(),
                        NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
                    );
                    let path = std::env::temp_dir().join(unique);
                    match std::fs::create_dir(&path) {
                        Ok(()) => return TempDir(path),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => panic!("create temp dir {path:?}: {error}"),
                    }
                }
                panic!("could not allocate unique temp dir for {prefix}");
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn manifest_end_to_end_builds_queryable_book() {
        let dir = tmpdir();
        write(dir.path(), "goog.txt", "google.com\nfull:g.co # exact\n");
        write(dir.path(), "ranges.txt", "8.8.8.0/24\n# comment\n1.1.1.1\n");
        write(
            dir.path(),
            "book.toml",
            r#"
epoch = 5
[[source]]
category = "google"
kind = "domains"
path = "goog.txt"

[[source]]
category = "google/dns"
kind = "cidrs"
path = "ranges.txt"
"#,
        );
        let (manifest, base) = Manifest::load(&dir.path().join("book.toml")).unwrap();
        let mut b = BookBuilder::new(manifest.epoch);
        let report = apply_manifest(&mut b, &manifest, &base).unwrap();
        assert_eq!(report.len(), 2);
        assert_eq!(report[0].1, 2);
        assert_eq!(report[1].1, 2);
        let book = AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap();
        let sel = book.resolve(&["google".into()]).unwrap();
        assert!(book.matches("maps.google.com", &sel));
        assert!(book.matches("8.8.8.8", &sel));
        let dns = book.resolve(&["google/dns".into()]).unwrap();
        assert!(!book.matches("maps.google.com", &dns));
        assert!(book.matches("1.1.1.1", &dns));
    }

    #[test]
    fn manifest_rejects_unknown_kind_and_bad_cidr_lines() {
        let dir = tmpdir();
        write(
            dir.path(),
            "bad-kind.toml",
            "[[source]]\ncategory='x'\nkind='nope'\npath='f'\n",
        );
        assert!(Manifest::load(&dir.path().join("bad-kind.toml")).is_err());

        write(dir.path(), "bad.txt", "not-an-ip\n");
        write(
            dir.path(),
            "book.toml",
            "[[source]]\ncategory='x'\nkind='cidrs'\npath='bad.txt'\n",
        );
        let (manifest, base) = Manifest::load(&dir.path().join("book.toml")).unwrap();
        let mut b = BookBuilder::new(0);
        assert!(apply_manifest(&mut b, &manifest, &base).is_err());

        write(dir.path(), "empty.txt", "# no usable entries\n");
        write(
            dir.path(),
            "empty-book.toml",
            "[[source]]\ncategory='x'\nkind='domains'\npath='empty.txt'\n",
        );
        let (manifest, base) = Manifest::load(&dir.path().join("empty-book.toml")).unwrap();
        let mut b = BookBuilder::new(0);
        let err = apply_manifest(&mut b, &manifest, &base).unwrap_err();
        assert!(err.to_string().contains("no supported entries"), "{err}");

        write(
            dir.path(),
            "bad-aws.json",
            r#"{"prefixes":[{"ip_prefix":"203.0.113.0/99","service":"EC2"}],
                "ipv6_prefixes":[]}"#,
        );
        write(
            dir.path(),
            "bad-provider.toml",
            "[[source]]\ncategory='aws'\nkind='aws-ip-ranges'\npath='bad-aws.json'\n",
        );
        let (manifest, base) = Manifest::load(&dir.path().join("bad-provider.toml")).unwrap();
        let mut b = BookBuilder::new(0);
        let err = apply_manifest(&mut b, &manifest, &base).unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid provider CIDR"),
            "{err:#}"
        );
    }

    #[test]
    fn v2fly_include_attrs_and_regexp_skip() {
        let dir = tmpdir();
        write(
            dir.path(),
            "google-base",
            "google.com\nregexp:^ads\\d+\\.example$\nfull:g.co @cn\n",
        );
        write(dir.path(), "google", "include:google-base\nkeyword:gvid\n");
        write(
            dir.path(),
            "book.toml",
            "[[source]]\ncategory='geosite/google'\nkind='v2fly-domains'\npath='google'\n",
        );
        let (manifest, base) = Manifest::load(&dir.path().join("book.toml")).unwrap();
        let mut b = BookBuilder::new(0);
        let report = apply_manifest(&mut b, &manifest, &base).unwrap();
        // google.com + full:g.co + keyword:gvid (regexp skipped).
        assert_eq!(report[0].1, 3);
        let book = AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap();
        let all = book.resolve(&["geosite/google".into()]).unwrap();
        let cn = book.resolve(&["geosite/google@cn".into()]).unwrap();
        assert!(book.matches("mail.google.com", &all));
        assert!(book.matches("g.co", &cn));
        assert!(!book.matches("mail.google.com", &cn));
    }

    #[test]
    fn v2fly_include_cycle_is_bounded() {
        let dir = tmpdir();
        write(dir.path(), "a", "include:b\n");
        write(dir.path(), "b", "include:a\n");
        let mut b = BookBuilder::new(0);
        let err = apply_v2fly(&mut b, "x", &dir.path().join("a")).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn v2fly_selective_include_affiliation_and_path_confinement() {
        let dir = tmpdir();
        write(
            dir.path(),
            "base",
            "normal.example\n\
             ad.example @ads &category-special\n\
             cn-ad.example @ads @cn &category-cn\n\
             foreign.example @!cn\n",
        );
        write(
            dir.path(),
            "filtered",
            "include:base @ads @-cn\ninclude:base @!cn\n",
        );
        write(
            dir.path(),
            "external",
            "external.example @ads &filtered\ninherited.example @ads &base\n",
        );
        write(
            dir.path(),
            "book.toml",
            "[[source]]\ncategory='geosite/filtered'\nkind='v2fly-domains'\npath='filtered'\n",
        );
        let (manifest, base) = Manifest::load(&dir.path().join("book.toml")).unwrap();
        let mut builder = BookBuilder::new(0);
        let report = apply_manifest(&mut builder, &manifest, &base).unwrap();
        assert_eq!(report[0].1, 4);
        let book = AddrBook::from_bytes(&builder.build_bytes().unwrap()).unwrap();

        let filtered = book.resolve(&["geosite/filtered".into()]).unwrap();
        assert!(book.matches("ad.example", &filtered));
        assert!(book.matches("foreign.example", &filtered));
        assert!(
            book.matches("external.example", &filtered),
            "repository-wide affiliations must reach the selected list"
        );
        assert!(
            book.matches("inherited.example", &filtered),
            "affiliations must be injected before an included list is filtered"
        );
        assert!(!book.matches("normal.example", &filtered));
        assert!(!book.matches("cn-ad.example", &filtered));

        let ads = book.resolve(&["geosite/filtered@ads".into()]).unwrap();
        assert!(book.matches("ad.example", &ads));
        assert!(book.matches("external.example", &ads));
        assert!(book.matches("inherited.example", &ads));
        assert!(!book.matches("foreign.example", &ads));
        let not_cn = book.resolve(&["geosite/filtered@!cn".into()]).unwrap();
        assert!(book.matches("foreign.example", &not_cn));
        let affiliated = book.resolve(&["geosite/category-special".into()]).unwrap();
        assert!(book.matches("ad.example", &affiliated));
        let affiliated_ads = book
            .resolve(&["geosite/category-special@ads".into()])
            .unwrap();
        assert!(book.matches("ad.example", &affiliated_ads));
        let filtered_out_affiliation = book.resolve(&["geosite/category-cn".into()]).unwrap();
        assert!(
            book.matches("cn-ad.example", &filtered_out_affiliation),
            "affiliations are global and resolve before include filters"
        );

        write(dir.path(), "escape", "include:../outside\n");
        let mut builder = BookBuilder::new(0);
        let err = apply_v2fly(&mut builder, "x", &dir.path().join("escape")).unwrap_err();
        assert!(
            err.to_string().contains("invalid v2fly include path"),
            "{err}"
        );

        let mut work = MAX_V2FLY_EXPANSION_WORK;
        assert!(charge_v2fly_work(&mut work, 1, Path::new("limit")).is_err());
    }

    #[test]
    fn aws_azure_gcp_provider_formats_parse() {
        let dir = tmpdir();
        write(
            dir.path(),
            "aws.json",
            r#"{"prefixes":[{"ip_prefix":"3.5.140.0/22","region":"x","service":"EC2"},
                            {"ip_prefix":"52.219.0.0/20","region":"x","service":"S3"}],
                "ipv6_prefixes":[{"ipv6_prefix":"2600:1f14::/35","region":"x","service":"EC2"}]}"#,
        );
        write(
            dir.path(),
            "azure.json",
            r#"{"values":[{"name":"Storage.EastUS","properties":{"addressPrefixes":["20.60.0.0/16"],"systemService":"AzureStorage"}},
                          {"name":"AzureCloud","properties":{"addressPrefixes":["13.64.0.0/11"],"systemService":""}}]}"#,
        );
        write(
            dir.path(),
            "gcp.json",
            r#"{"prefixes":[{"ipv4Prefix":"8.8.4.0/24"},
                            {"ipv4Prefix":"34.80.0.0/15","service":"Google Cloud","scope":"asia-east1"},
                            {"ipv6Prefix":"2600:1900::/28","service":"Google Cloud"}]}"#,
        );
        write(
            dir.path(),
            "book.toml",
            r#"
[[source]]
category = "aws"
kind = "aws-ip-ranges"
path = "aws.json"
[[source]]
category = "azure"
kind = "azure-service-tags"
path = "azure.json"
[[source]]
category = "gcp"
kind = "gcp-cloud-json"
path = "gcp.json"
"#,
        );
        let (manifest, base) = Manifest::load(&dir.path().join("book.toml")).unwrap();
        let mut b = BookBuilder::new(0);
        apply_manifest(&mut b, &manifest, &base).unwrap();
        let book = AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap();

        let aws = book.resolve(&["aws".into()]).unwrap();
        let ec2 = book.resolve(&["aws/ec2".into()]).unwrap();
        let s3 = book.resolve(&["aws/s3".into()]).unwrap();
        assert!(book.matches("3.5.140.9", &aws));
        assert!(book.matches("3.5.140.9", &ec2));
        assert!(!book.matches("3.5.140.9", &s3));
        assert!(book.matches("2600:1f14::1", &ec2));

        let storage = book.resolve(&["azure/azurestorage".into()]).unwrap();
        assert!(book.matches("20.60.1.2", &storage));
        let azure = book.resolve(&["azure".into()]).unwrap();
        assert!(book.matches("13.64.0.1", &azure));
        // Empty systemService falls back to the tag name's first segment.
        assert!(book.resolve(&["azure/azurecloud".into()]).is_ok());

        let gcp = book.resolve(&["gcp".into()]).unwrap();
        let gcloud = book.resolve(&["gcp/google-cloud".into()]).unwrap();
        assert!(book.matches("8.8.4.4", &gcp));
        assert!(!book.matches("8.8.4.4", &gcloud));
        assert!(book.matches("34.81.0.1", &gcloud));
        assert!(book.matches("2600:1900::1", &gcloud));
    }

    #[test]
    fn service_segment_sanitizes_labels() {
        assert_eq!(service_segment("Google Cloud"), "google-cloud");
        assert_eq!(service_segment("EC2"), "ec2");
        assert_eq!(service_segment("A/B"), "a-b");
        assert_eq!(service_segment(""), "");
    }

    #[test]
    fn provider_cidrs_require_network_addresses_and_prefix_lengths() {
        let mut builder = BookBuilder::new(0);
        let file = Path::new("provider.json");
        assert!(add_provider_cidr(&mut builder, "x", "203.0.113.7/24", file)
            .unwrap_err()
            .to_string()
            .contains("host bits"));
        assert!(add_provider_cidr(&mut builder, "x", "203.0.113.7", file)
            .unwrap_err()
            .to_string()
            .contains("must be a CIDR"));
        add_provider_cidr(&mut builder, "x", "203.0.113.0/24", file).unwrap();
        assert!(
            serde_json::from_str::<AzureTags>(
                r#"{"values":[{"name":"Broken","properties":{"systemService":"Storage"}}]}"#
            )
            .is_err(),
            "missing Azure addressPrefixes must not deserialize as an empty tag"
        );
        assert!(
            serde_json::from_str::<AwsRanges>(r#"{"prefixes":[]}"#).is_err(),
            "missing AWS ipv6_prefixes must not deserialize as an empty family"
        );
    }
}
