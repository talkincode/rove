#![allow(dead_code)]

pub const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUAhO4y5A+Ol+O93RC/xCs0+kTRkkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYzMDE2NTMzMloXDTI2MDcw
MTE2NTMzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4czDicziIZKbupNwxPgbYa9jMAw1U9ypRAYUSlqcHG+5
shd/YkBxZ8fCZXDwr62GTVikRnyo99kzAeilgW22SgmlXzA8JKBpEzlN6YpZDhTh
yowwTtGts83z4mRWStXtHHzx1oomJTFpuwtvH6uNmvvVq8QGP9tRcPYXtJc80mZk
6qyFooKKxH8FinyqBpE0gLCnZoz9t/5CNTrZvkXt0kaZU9W5IwJGLw1ykktmzsC3
fl+vr24iHORg0HFI465tdFRN7fOhq9XMOdxxoEo9Fbe1J6AbwItkBMS6OJ8pMAMn
GOUqLDxvUxpICXUzvw6tRbfDjRjhRNAPJflJ5irmpQIDAQABo1MwUTAdBgNVHQ4E
FgQUTTYc3xMzdxugRyWHg9wY0SSWEXQwHwYDVR0jBBgwFoAUTTYc3xMzdxugRyWH
g9wY0SSWEXQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAvMhS
6sNjihQIHAMdZbQcxkBa1GsORK28flXAS1s41WI192gq6lCmP27mtig/vTzYEusY
qn0vMNhWaZXaAL1kUG5NMONrup5KA9N+vgdCClpGl9ffSrSMJciqvQZ/e3n/Eotn
fwJDlqASKGJ3ihQiEXfJx5oVpKA2VKSKxxlwKDmEPPUiwrbg3UH6iQlwFSed8Ypn
83niMaSI8VZf/Y2wtNldAOSW7K8jCvcfTCgO27qUepWAAnOl3Cy4NELtpZCTh6HH
ohVgaaT/RuT8aZbczsj7/5HH527DPpgJBmxKcOZ/e+jmdKtRsFnaoBziBr/CKwq4
IJsCUBadjBA5aZyBXg==
-----END CERTIFICATE-----";

pub const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzMOJzOIhkpu6
k3DE+Bthr2MwDDVT3KlEBhRKWpwcb7myF39iQHFnx8JlcPCvrYZNWKRGfKj32TMB
6KWBbbZKCaVfMDwkoGkTOU3pilkOFOHKjDBO0a2zzfPiZFZK1e0cfPHWiiYlMWm7
C28fq42a+9WrxAY/21Fw9he0lzzSZmTqrIWigorEfwWKfKoGkTSAsKdmjP23/kI1
Otm+Re3SRplT1bkjAkYvDXKSS2bOwLd+X6+vbiIc5GDQcUjjrm10VE3t86Gr1cw5
3HGgSj0Vt7UnoBvAi2QExLo4nykwAycY5SosPG9TGkgJdTO/Dq1Ft8ONGOFE0A8l
+UnmKualAgMBAAECggEAGQ0luJkhkYX5fxaykTfRmeHiiEcid35ozSI7iBBLd6Ax
ov+WY2kw68mu2KBSI7uFxfkKqMNV38GaNiEAk75/VfGCBnCMi6e8YKSf70QpIzXP
4y/wgB4lPmigIULui/j2CI4YKqxDFSdJSrY3CvV2jXZZO2hRJS6I95ZmBOQunE0I
laMoBeZrhI1yJGFu+KRM2759jRVFl5JAqsf8JRJQk9PIe2rB3mSaCRKyKS1gnDIK
iiddOdcxf3hJSoKaqF3z5h+qK1OxZNiteKNL5fuvX+2KmN/7rQcwttLQqbXGdnsw
vNOyyfnB5VpvxnKy5gbfFNI3fEovHtT7ELWhTIKAIQKBgQDx7O9GO05XnlUoGOTs
R7Ccrd+sqMDMWIo9cA7AD63z9Cy83PuOoOuAvmfHKGvCTDUPrVJ90X6nnbeCdLxX
NwWWQMTKwhq/vZaZ6eCVSFSXCdvbRRYVYFv5xxbIaoFnguiXEGhd24sKiGPuw9GN
HHSZxxiu+Ef6s6q5Cz+3M/9ffQKBgQDu76o/QqRb4tivbrh4+yT8PHbe8Ro53RUE
oNB0n4sjKXgsalhFuAv7fw6MDCFHSxHGBL2lTtV7mZ/VEgT3fB70j/929EsSteAx
dNHonxhZ+YSoHu+v8FU85F9XpPo5qEHY8vW3lsYHxHf9fOZSx0wM9Ok36aUEPz9k
5x7C9jMcSQKBgCevxaTQz85B1Bhq1QsJy6g4QcwyNsaO88aWXmUVbWTqtngZDE9e
iKOrGJ0sPVk3ZTD4LuMi/dMDZXpKKidoiEsYvu/AHeE8ebswCb6TigTpAh8bWz8Q
eqYkCdHA3w+bAwrdDzHudQW6UCJ4DyVF+L7NUXhKlIxE8wm+Faq5JfiFAoGADsEw
Ay4LVj1A4jx1Gctwcj8NnCDJXM9hL+L6XGlJv0cdS6jZgJyn6MTk0hMhrvRcyZyb
VWzz0+kdrJurQNkiVDncLa1SQXqHuKYdHD9O0qeM4JDgfj3aFaOIm7HtXcgdINeI
AulFm08vlbCzzGLQOHCbQj+kWAnL0WBQTvvDFjkCgYEA7LA+RcGSZQjXw7PYm0Z2
410OnmEWlGBiF5h+jWGrWLpSEH632KdAryjXnw5L2QGnzc/7bpsINX0Kvpstut1m
4yU5RFQ1CphRafbztDMLnv5dO0gkqHWHvxE97MTBV/W9UZl6c52RB+5a8H+/QSbZ
v6K3aPttpZErFvOSVbzWaCY=
-----END PRIVATE KEY-----";

// ---------------------------------------------------------------------------
// Snapshot construction helpers
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use rove::model::{RawAction, RawEgress, RawRoute, RawRoutingPolicy, RawUpstream};
#[allow(unused_imports)]
use std::collections::HashMap;

/// Test-only sugar for building a routing policy.
///
/// The wire model is deliberately normalized (an ordered route list plus a
/// separate named-egress table), which is verbose to spell out in a test that
/// only cares about "these hosts take an egress, these are blocked". `PolicySpec`
/// is the denormalized shorthand; [`PolicySpec::expand`] lowers it into the
/// real `RawRoutingPolicy` + `RawEgress` pair the compiler consumes.
///
/// Route order is block-first, matching the block-veto semantics of
/// `Snapshot::decide_with_sniff`.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct PolicySpec {
    /// Backend for hosts matched by `routed`. `None` = no egress route is emitted.
    pub egress: Option<RawUpstream>,
    /// Backend used when no route matches. `None` = direct.
    pub default_egress: Option<RawUpstream>,
    /// Selectors routed through `egress`.
    pub routed: Vec<String>,
    /// Selectors denied outright.
    pub blocked: Vec<String>,
}

#[allow(dead_code)]
impl PolicySpec {
    /// Lower into a routing policy plus the named egresses it references,
    /// using `id` to namespace the generated egress ids.
    pub fn expand(self, id: &str) -> (RawRoutingPolicy, HashMap<String, RawEgress>) {
        let mut egresses = HashMap::new();
        let mut routes = Vec::new();

        if !self.blocked.is_empty() {
            routes.push(RawRoute {
                selectors: self.blocked,
                action: RawAction::Block,
            });
        }
        // A routed selector with no egress would silently vanish from the
        // compiled policy, quietly making the test assert nothing.
        assert!(
            self.egress.is_some() || self.routed.is_empty(),
            "PolicySpec {id:?}: routed selectors require an egress"
        );
        if let Some(backend) = self.egress {
            let egress_id = format!("{id}-egress");
            egresses.insert(egress_id.clone(), RawEgress::Upstream { backend });
            if !self.routed.is_empty() {
                routes.push(RawRoute {
                    selectors: self.routed,
                    action: RawAction::Egress { egress: egress_id },
                });
            }
        }
        let default_egress = self.default_egress.map(|backend| {
            let egress_id = format!("{id}-default");
            egresses.insert(egress_id.clone(), RawEgress::Upstream { backend });
            egress_id
        });

        (
            RawRoutingPolicy {
                routes,
                default_egress,
            },
            egresses,
        )
    }

    /// Lower into the `routing_policies` / `egresses` tables of a snapshot.
    pub fn into_tables(
        self,
        id: &str,
    ) -> (
        HashMap<String, RawRoutingPolicy>,
        HashMap<String, RawEgress>,
    ) {
        let (policy, egresses) = self.expand(id);
        (HashMap::from([(id.to_string(), policy)]), egresses)
    }
}
