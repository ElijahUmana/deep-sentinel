"""Configuration management for DeepSentinel."""
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # Auth0
    auth0_domain: str = field(default_factory=lambda: os.environ.get("AUTH0_DOMAIN", ""))
    auth0_client_id: str = field(default_factory=lambda: os.environ.get("AUTH0_CLIENT_ID", ""))
    auth0_client_secret: str = field(default_factory=lambda: os.environ.get("AUTH0_CLIENT_SECRET", ""))

    # GitHub
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", ""))

    # Slack
    slack_bot_token: str = field(default_factory=lambda: os.environ.get("SLACK_BOT_TOKEN", ""))

    # Macroscope
    macroscope_api_key: str = field(default_factory=lambda: os.environ.get("MACROSCOPE_API_KEY", ""))
    macroscope_project_id: str = field(default_factory=lambda: os.environ.get("MACROSCOPE_PROJECT_ID", ""))

    # Ghost
    ghost_connection_string: str = field(default_factory=lambda: os.environ.get("GHOST_CONNECTION_STRING", ""))

    # TrueFoundry
    truefoundry_api_key: str = field(default_factory=lambda: os.environ.get("TRUEFOUNDRY_API_KEY", ""))
    truefoundry_base_url: str = field(default_factory=lambda: os.environ.get("TRUEFOUNDRY_BASE_URL", "https://gateway.truefoundry.ai"))

    # Overmind
    overmind_api_key: str = field(default_factory=lambda: os.environ.get("OVERMIND_API_KEY", ""))

    # Aerospike
    aerospike_host: str = field(default_factory=lambda: os.environ.get("AEROSPIKE_HOST", "127.0.0.1"))
    aerospike_port: int = field(default_factory=lambda: int(os.environ.get("AEROSPIKE_PORT", "3000")))

    # OpenAI (fallback if TrueFoundry unavailable)
    openai_api_key: str = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY", ""))
