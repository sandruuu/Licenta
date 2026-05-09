# README

## About

This is the official Wails React template.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

To build a redistributable, production mode package, use `wails build`.

## Endpoint Identity

The app is the posture runtime of the unified Endpoint Agent documented in the [Endpoint Agent README](../README.md). It uses `endpoint-agent/device-health-app/tpmauth` as a wrapper over `endpoint-agent/shared/endpointidentity`, the same endpoint identity implementation used by Connect-App. Both runtimes share one TPM/software endpoint key and one Cloud-issued Device Certificate (`component=endpoint`) cached in the unified endpoint folder (`ZTNA_ENDPOINT_DIR`, or the machine-wide endpoint directory by default).

## Test/Compile Note

`endpoint-agent/device-health-app/main.go` uses `//go:embed all:frontend/dist`, so `frontend/dist` must exist for `go build` or `go test`.
Run `npm ci && npm run build` in `endpoint-agent/device-health-app/frontend` before Go builds/tests when the dist directory is missing.
