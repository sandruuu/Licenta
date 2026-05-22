# Feature Modules

`features/` is a separate Go module for endpoint capabilities that are not wired into `agent/` yet.

Run its tests independently:

```powershell
cd features
go test ./...
```

The DNS resolver/control prototype was promoted into `agent/internal/service/dns-resolver`, `agent/internal/service/dns-control`, and `agent/internal/service/protected-resources`. `features/dnsresolver` keeps only a tiny compatibility contract for dormant prototypes that still share the `Mapping` type.

Current remaining packages include device posture, catalog normalization, TUN/network routing, TCP proxying, Gateway relay/tunnel, PA clients, and process identity lookup.

Keep this module independent from `agent/internal/...`. When a capability is ready, wire it into `agent` through an explicit interface and focused service tests.
