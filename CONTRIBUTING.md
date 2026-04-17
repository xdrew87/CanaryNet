# Contributing to CanaryNet

Thank you for your interest in contributing! This document outlines how to get started.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## How to Contribute

### Reporting Bugs

1. Check that the bug hasn't already been reported in [Issues](../../issues)
2. Open a new issue using the **Bug Report** template
3. Include as much detail as possible: steps to reproduce, expected vs actual behavior, environment

### Suggesting Features

1. Open a new issue using the **Feature Request** template
2. Describe the problem you want to solve and your proposed solution
3. Discuss before opening a PR for large changes

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes — see code style notes below
4. Test your changes: `pip install -r requirements.txt && python main.py db init`
5. Commit with a clear message: `git commit -m "feat: add X to Y"`
6. Push to your fork: `git push origin feature/my-feature`
7. Open a Pull Request against `main`

## Code Style

- Python 3.11+
- Follow PEP 8
- Use type hints on all public functions
- Add docstrings to new modules and public classes
- Keep functions focused and small
- No hardcoded credentials — always use environment variables

## Commit Message Format

Use conventional commits where possible:
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `refactor:` — code change that neither fixes a bug nor adds a feature
- `test:` — adding or updating tests
- `chore:` — maintenance, dependency updates

## Setting Up Locally

```bash
git clone https://github.com/your-org/canarynet.git
cd canarynet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py db init
python main.py serve
```

## Security Issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md).
