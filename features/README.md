# Feature Modules

`features/` is a separate Go module for endpoint capabilities that are not wired into `agent/` yet.

Run its tests independently:

```powershell
cd features
go test ./...
```

Current packages include device posture, catalog normalization, DNS resolver/control, TUN/network routing, TCP proxying, Gateway relay/tunnel, PA clients, and process identity lookup.

Keep this module independent from `agent/internal/...`. When a capability is ready, wire it into `agent` through an explicit interface and focused service tests.
