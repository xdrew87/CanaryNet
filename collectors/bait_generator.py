"""
Bait file generator.

IMPORTANT: All generated content is for DEFENSIVE RESEARCH ONLY.
All credentials embedded in bait files are FAKE and NON-FUNCTIONAL.
This module is intended for use on infrastructure you OWN and have
AUTHORIZATION to monitor. Never deploy bait files on systems you do
not control.
"""
from __future__ import annotations

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Safety header included in every generated file
# ---------------------------------------------------------------------------
_SAFETY_HEADER = (
    "# BAIT FILE — FOR DEFENSIVE RESEARCH ONLY\n"
    "# CREDENTIALS ARE FAKE AND NON-FUNCTIONAL\n"
    "# Deployed on authorized infrastructure to detect unauthorized access.\n"
    "# If you found this file: STOP. You are accessing a monitored system.\n"
)


class BaitGenerator:
    """Generates honeypot bait files with fake, non-functional credentials."""

    # ------------------------------------------------------------------
    # Individual generators
    # ------------------------------------------------------------------

    def generate_env_file(self, canary_token: str) -> str:
        """Return .env bait content with clearly fake credentials."""
        return (
            f"{_SAFETY_HEADER}\n"
            "# Application Environment — DO NOT SHARE\n\n"
            "APP_ENV=production\n"
            "DEBUG=false\n\n"
            "# Database\n"
            "DATABASE_URL=postgresql://FAKE_DB_USER:BAIT_PASSWORD_DO_NOT_USE@db.internal:5432/appdb\n\n"
            "# GitHub\n"
            "GITHUB_PAT=ghp_FAKEBAITTOKEN1234567890ABCDEFGHIJ\n"
            "GITHUB_ORG=example-org\n\n"
            "# AWS (FAKE — do not use)\n"
            "AWS_ACCESS_KEY_ID=AKIAFAKEBAITHONEYPOT1\n"
            "AWS_SECRET_ACCESS_KEY=FAKEBAIT/SecretKey/DoNotUse/HoneypotOnly+ABC\n"
            "AWS_REGION=us-east-1\n\n"
            "# Stripe (FAKE)\n"
            "STRIPE_SECRET_KEY=sk_live_FAKEBAITSTRIPE0000000000000000000\n\n"
            "# Internal\n"
            f"# Tracking: {canary_token}\n"
            f"TELEMETRY_ENDPOINT=https://api.internal/telemetry?token={canary_token}\n"
        )

    def generate_github_actions_file(self, canary_token: str) -> str:
        """Return a fake GitHub Actions workflow with bait credentials."""
        return (
            f"{_SAFETY_HEADER}\n"
            "name: Deploy to Production\n\n"
            "on:\n"
            "  push:\n"
            "    branches: [main]\n\n"
            "jobs:\n"
            "  deploy:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n\n"
            "      - name: Configure AWS (BAIT — FAKE CREDENTIALS)\n"
            "        env:\n"
            "          AWS_ACCESS_KEY_ID: AKIAFAKEBAITHONEYPOT1\n"
            "          AWS_SECRET_ACCESS_KEY: FAKEBAIT/SecretKey/DoNotUse/HoneypotOnly+ABC\n"
            "        run: |\n"
            "          aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID\n"
            "          aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY\n\n"
            "      - name: Notify deployment (canary beacon)\n"
            f"        run: curl -s https://api.internal/deploy?token={canary_token} || true\n\n"
            "      - name: Deploy\n"
            "        env:\n"
            "          GITHUB_PAT: ghp_FAKEBAITTOKEN1234567890ABCDEFGHIJ\n"
            "        run: echo 'Deploying...'\n"
        )

    def generate_config_json(self, canary_token: str) -> str:
        """Return a fake config.json with bait API keys."""
        config = {
            "_comment": "BAIT FILE — FOR DEFENSIVE RESEARCH ONLY — CREDENTIALS ARE FAKE",
            "environment": "production",
            "api": {
                "key": "FAKEBAIT-API-KEY-0000-0000-000000000000",
                "secret": "FAKEBAIT_SECRET_DO_NOT_USE_HONEYPOT_ONLY",
                "endpoint": "https://api.internal/v2",
                "canary_token": canary_token,
            },
            "database": {
                "host": "db.internal",
                "port": 5432,
                "name": "appdb",
                "user": "FAKE_DB_USER",
                "password": "BAIT_PASSWORD_DO_NOT_USE",
            },
            "auth": {
                "jwt_secret": "FAKEBAIT_JWT_SECRET_HONEYPOT_ONLY_DO_NOT_USE",
                "admin_token": "FAKEBAIT_ADMIN_TOKEN_0000000000000000",
            },
        }
        return f"// BAIT FILE — FOR DEFENSIVE RESEARCH ONLY — CREDENTIALS ARE FAKE AND NON-FUNCTIONAL\n{json.dumps(config, indent=2)}\n"

    def generate_pat_readme(self, canary_token: str) -> str:
        """Return a README that appears to accidentally expose a PAT (obviously fake)."""
        return (
            f"{_SAFETY_HEADER}\n"
            "# dev-tools-2024\n\n"
            "Internal development utilities.\n\n"
            "## Quick Setup\n\n"
            "```bash\n"
            "git clone https://github.com/example-org/dev-tools-2024\n"
            "cd dev-tools-2024\n"
            "pip install -r requirements.txt\n"
            "```\n\n"
            "## Authentication\n\n"
            "Use the team PAT below (read-only, expires 2025-12-31):\n\n"
            "```\n"
            "ghp_FAKEBAITTOKEN1234567890ABCDEFGHIJ\n"
            "```\n\n"
            "> **Note:** Rotate this token immediately if you see it in logs.\n\n"
            "## Internal Endpoints\n\n"
            f"- Status: https://api.internal/status?auth={canary_token}\n"
            "- Dashboard: https://internal.example.com/dashboard\n\n"
            "## Contact\n\n"
            "Reach the DevOps team at devops@example.com\n"
        )

    def generate_fake_api_docs(self, canary_token: str) -> str:
        """Return markdown API docs with obviously fake example keys."""
        return (
            f"{_SAFETY_HEADER}\n"
            "# Internal API Documentation\n\n"
            "Base URL: `https://api.internal/v2`\n\n"
            "## Authentication\n\n"
            "Include your API key in the `X-API-Key` header.\n\n"
            "**Example key (FAKE — for documentation only):**\n"
            "```\n"
            "FAKEBAIT-API-KEY-0000-0000-000000000000\n"
            "```\n\n"
            "## Endpoints\n\n"
            "### GET /status\n\n"
            "```bash\n"
            "curl -H 'X-API-Key: FAKEBAIT-API-KEY-0000-0000-000000000000' \\\n"
            f"     https://api.internal/v2/status?_t={canary_token}\n"
            "```\n\n"
            "### POST /deploy\n\n"
            "```json\n"
            '{\n'
            '  "environment": "production",\n'
            '  "token": "FAKEBAIT_DEPLOY_TOKEN_DO_NOT_USE",\n'
            f'  "canary": "{canary_token}"\n'
            '}\n'
            "```\n\n"
            "## Error Codes\n\n"
            "| Code | Meaning |\n"
            "|------|----------|\n"
            "| 401  | Invalid API key |\n"
            "| 403  | Forbidden |\n"
            "| 429  | Rate limited |\n"
        )

    # ------------------------------------------------------------------
    # Bundle generator
    # ------------------------------------------------------------------

    def generate_bait_package(
        self, output_dir: str, canary_tokens: dict[str, str]
    ) -> list[str]:
        """
        Write all bait files to output_dir.

        canary_tokens: mapping of file_type -> token string
          e.g. {"env": "abc123", "workflow": "def456", ...}

        Returns list of absolute file paths written.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        written: list[str] = []

        def _write(filename: str, content: str) -> None:
            path = out / filename
            path.write_text(content, encoding="utf-8")
            written.append(str(path))

        _write(".env", self.generate_env_file(canary_tokens.get("env", "NONE")))
        _write(
            "deploy.yml",
            self.generate_github_actions_file(canary_tokens.get("workflow", "NONE")),
        )
        _write(
            "config.json",
            self.generate_config_json(canary_tokens.get("config", "NONE")),
        )
        _write(
            "README.md",
            self.generate_pat_readme(canary_tokens.get("pat", "NONE")),
        )
        _write(
            "API_DOCS.md",
            self.generate_fake_api_docs(canary_tokens.get("api_doc", "NONE")),
        )
        return written
