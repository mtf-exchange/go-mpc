# Contributing

## Development Setup

Requires Go 1.24 or later.

```bash
go test -race ./...
```

## Code Style

- `gofmt` and `go vet` must pass
- `staticcheck` must pass
- Error messages use the format: `"dkls23 FunctionName: description"`

## Testing

- Maintain 90%+ test coverage
- Add tests for new public API functions and error paths
- Run with `-race` to catch concurrency issues

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality
- Update CHANGELOG.md

## Security-Sensitive Changes

Changes to cryptographic code (DKG, signing, VOLE, OT, key refresh) require careful review. Please coordinate with maintainers before submitting large changes to these areas.
