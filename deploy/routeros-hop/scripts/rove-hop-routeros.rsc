# rove-hop RouterOS container deploy (reverse-only)
# Docs: deploy/routeros-hop/GUIDE.md
#
# Prerequisites:
#   1) container package installed
#   2) docker-save image already on device (default name: rove-hop-arm64.tar)
#   3) set :global variables first (see env.example), then:
#        /import file-name=rove-hop-routeros.rsc
#
# Naming: reverse-hop-id MUST look like rove-hop-<region>[-site][-n]
#   examples: rove-hop-jp , rove-hop-cn-office-ax2

:local hopId $RoveHopId
:local edge $RoveHopEdge
:local token $RoveHopToken
:local serverName $RoveHopServerName
:local insecure $RoveHopInsecure
:local image $RoveHopImage
:local veth $RoveHopVeth
:local addr $RoveHopAddr
:local gw $RoveHopGateway
:local hostAddr $RoveHopHostAddr
:local root $RoveHopRoot
:local cname $RoveHopName
:local memHigh $RoveHopMemHigh
:local dns $RoveHopDns
:local maxStreams $RoveHopMaxStreams

:if ([:typeof $hopId] = "nothing" || $hopId = "") do={
  :error "RoveHopId is required (example: rove-hop-jp). See HOP-ID-NAMING.md"
}
:if ([:typeof $edge] = "nothing" || $edge = "") do={
  :error "RoveHopEdge is required (example: edge.example.com:9443)"
}
:if ([:typeof $token] = "nothing" || $token = "" || $token = "REPLACE_WITH_REVERSE_HOP_TOKEN") do={
  :error "RoveHopToken is required and must not be the placeholder"
}
:if ([:typeof $image] = "nothing" || $image = "") do={ :set image "rove-hop-arm64.tar" }
:if ([:typeof $veth] = "nothing" || $veth = "") do={ :set veth "rove-hop-veth" }
:if ([:typeof $addr] = "nothing" || $addr = "") do={ :set addr "172.30.68.2/30" }
:if ([:typeof $gw] = "nothing" || $gw = "") do={ :set gw "172.30.68.1" }
:if ([:typeof $hostAddr] = "nothing" || $hostAddr = "") do={ :set hostAddr "172.30.68.1/30" }
:if ([:typeof $root] = "nothing" || $root = "") do={ :set root "/rove-hop-root" }
:if ([:typeof $cname] = "nothing" || $cname = "") do={ :set cname "rove-hop" }
:if ([:typeof $memHigh] = "nothing" || $memHigh = "") do={ :set memHigh "67108864" }
:if ([:typeof $dns] = "nothing" || $dns = "") do={ :set dns "1.1.1.1" }
:if ([:typeof $maxStreams] = "nothing" || $maxStreams = "") do={ :set maxStreams "256" }
:if ([:typeof $serverName] = "nothing" || $serverName = "") do={
  :set serverName [:pick $edge 0 [:find $edge ":"]]
}
:if ([:typeof $insecure] = "nothing" || $insecure = "") do={ :set insecure "no" }

# hop_id prefix guard (soft): must start with rove-hop-
:if ([:pick $hopId 0 8] != "rove-hop-") do={
  :error ("RoveHopId must start with rove-hop- ; got: " . $hopId)
}

:put ("rove-hop deploy: name=" . $cname . " hop_id=" . $hopId . " edge=" . $edge)

# --- veth ---
:if ([:len [/interface veth find where name=$veth]] = 0) do={
  /interface veth add name=$veth address=$addr gateway=$gw
  :put ("created veth " . $veth)
} else={
  :put ("veth exists: " . $veth)
}

:if ([:len [/ip address find where interface=$veth and comment="rove-hop"]] = 0) do={
  /ip address add address=$hostAddr interface=$veth comment="rove-hop"
  :put ("added host address " . $hostAddr)
}

# Optional: if you have NO global masquerade, uncomment and adjust:
# /ip firewall nat add chain=srcnat src-address=172.30.68.0/30 action=masquerade comment="rove-hop-masq"

# --- stop/remove existing container with same name ---
:local existing [/container find where name=$cname]
:if ([:len $existing] > 0) do={
  :put "stopping existing container..."
  /container stop $existing
  :delay 3s
  /container remove $existing
  :put "removed old container"
}

# --- build cmd (reverse-only) ---
:local cmd ("--reverse-quic " . $edge . " --reverse-hop-id " . $hopId . " --reverse-token " . $token . " --reverse-server-name " . $serverName . " --reverse-max-streams " . $maxStreams . " --access-log-disable --dns-server " . $dns)
:if (($insecure = "yes") || ($insecure = "true")) do={
  :set cmd ($cmd . " --reverse-insecure")
}

:put ("cmd=" . $cmd)

/container add \
  file=$image \
  interface=$veth \
  root-dir=$root \
  name=$cname \
  entrypoint="/usr/local/bin/rove-hop" \
  cmd=$cmd \
  dns=$dns \
  logging=yes \
  start-on-boot=yes \
  memory-high=$memHigh \
  comment=("rove-hop reverse " . $hopId)

:delay 2s
:local cid [/container find where name=$cname]
:if ([:len $cid] = 0) do={
  :error "container add failed; check /log print where topics~\"container\""
}

# wait extract (arch populated)
:local i 0
:while ($i < 60) do={
  :local arch [/container get $cid arch]
  :if ($arch != "") do={
    :put ("image ready arch=" . $arch)
    :set i 60
  } else={
    :set i ($i + 1)
    :delay 1s
  }
}

/container start $cid
:delay 2s

:local run [/container get $cid running]
:local mem [/container get $cid memory-current]
:put ("started running=" . $run . " memory-current=" . $mem)
:put "Next: /log print where topics~\"container\"  and verify edge session for hop_id"
:put "DONE rove-hop deploy"
