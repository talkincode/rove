# Remove rove-hop container and network objects created by rove-hop-routeros.rsc
# Does NOT delete the image tar by default (flash-safe manual step).
#
# Optional globals (defaults shown):
#   RoveHopName   = "rove-hop"
#   RoveHopVeth   = "rove-hop-veth"

:local cname $RoveHopName
:local veth $RoveHopVeth
:if ([:typeof $cname] = "nothing" || $cname = "") do={ :set cname "rove-hop" }
:if ([:typeof $veth] = "nothing" || $veth = "") do={ :set veth "rove-hop-veth" }

:put ("rove-hop remove: container=" . $cname . " veth=" . $veth)

:local cid [/container find where name=$cname]
:if ([:len $cid] > 0) do={
  /container stop $cid
  :delay 3s
  /container remove $cid
  :put "container removed"
} else={
  :put "container not found"
}

:foreach a in=[/ip address find where interface=$veth] do={
  /ip address remove $a
}
:foreach a in=[/ip address find where comment="rove-hop"] do={
  /ip address remove $a
}

:if ([:len [/interface veth find where name=$veth]] > 0) do={
  /interface veth remove [find where name=$veth]
  :put ("veth removed: " . $veth)
}

# Optional NAT leftovers from *this* deploy only.
# Exact-match comments — do NOT use comment~"rove-hop" (would also hit
# rove-hop-bench / other experiment rules).
:foreach n in=[/ip firewall nat find where comment="rove-hop" or comment="rove-hop-masq"] do={
  /ip firewall nat remove $n
  :put "removed nat rule with exact rove-hop comment"
}

:put "Image tar left on disk. Remove manually if desired: /file remove [find name~\"rove-hop\"]"
:put "DONE rove-hop remove"
