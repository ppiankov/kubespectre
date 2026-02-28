# Contributing to kubespectre

## Development

```bash
make build    # Build binary
make test     # Run tests with race detection
make lint     # Run linter
make fmt      # Format code
make coverage # Run tests with coverage report
```

## Code Style

- Go conventions: gofmt, govet, golangci-lint
- Tests alongside source files (*_test.go)
- Comments explain "why" not "what"

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## Security

If you discover a security vulnerability, please report it responsibly.
See [SECURITY.md](SECURITY.md) for details.
