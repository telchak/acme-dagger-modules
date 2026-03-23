"""AcmeCorp Python backend builder — standardized, cached, production-ready."""

from typing import Annotated

import dagger
from dagger import DefaultPath, Doc, check, dag, function, object_type


# Approved base images — only these are allowed in production containers.
APPROVED_BASE_IMAGE = "python:3.13-slim"

# Minimum test coverage threshold enforced across all backend services.
MIN_COVERAGE_PERCENT = 80


@object_type
class AcmeBackend:
    """Build and test Python backends the AcmeCorp way.

    Enforces:
    - Organization-approved base images (python:3.13-slim)
    - Standardized cache volumes for pip
    - Health check endpoint convention (/health)
    - Cloud Run-compatible entrypoint and port
    - Minimum 80% test coverage
    - CycloneDX SBOM generation for vulnerability tracking
    """

    def _base_container(self, source: dagger.Directory) -> dagger.Container:
        """Standard Python container with source and cached deps."""
        return (
            dag.container()
            .from_(APPROVED_BASE_IMAGE)
            .with_workdir("/app")
            .with_directory("/app", source)
            .with_mounted_cache("/root/.cache/pip", dag.cache_volume("acme-pip"))
            .with_exec(["pip", "install", "-r", "requirements.txt"])
        )

    @function
    def build(
        self,
        source: Annotated[dagger.Directory, Doc("Python backend source directory")],
        port: Annotated[int, Doc("Application port")] = 8080,
    ) -> dagger.Container:
        """Build a production-ready FastAPI container.

        Uses the organization-approved base image and standardized
        entrypoint. Returns a Container that can be passed directly
        to acme-deploy.
        """
        return (
            dag.python_build()
            .with_base(APPROVED_BASE_IMAGE)
            .with_pip_cache(dag.cache_volume("acme-pip"))
            .build(source=source)
            .with_env_variable("PORT", str(port))
            .with_exposed_port(port)
            .with_label("org.opencontainers.image.vendor", "AcmeCorp")
            .with_entrypoint([
                "uvicorn", "src.main:app",
                "--host", "0.0.0.0", "--port", str(port),
            ])
        )

    @function
    @check
    async def test(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Python backend source directory"),
            DefaultPath("."),
        ],
        coverage: Annotated[bool, Doc("Enforce minimum coverage threshold")] = True,
    ) -> str:
        """Run the test suite with AcmeCorp conventions.

        Uses pytest with verbose output, short tracebacks, and coverage
        reporting. Fails if coverage drops below the org-wide threshold.
        """
        pytest_args = ["pytest", "-v", "--tb=short"]
        if coverage:
            pytest_args.extend([
                f"--cov=src", "--cov-report=term-missing",
                f"--cov-fail-under={MIN_COVERAGE_PERCENT}",
            ])
        pytest_args.append("tests/")

        return await (
            self._base_container(source)
            .with_exec(pytest_args)
            .stdout()
        )

    @function
    @check
    async def lint(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Python backend source directory"),
            DefaultPath("."),
        ],
    ) -> str:
        """Run linting (ruff) on the source code."""
        return await (
            dag.container()
            .from_(APPROVED_BASE_IMAGE)
            .with_workdir("/app")
            .with_directory("/app", source)
            .with_exec(["pip", "install", "ruff"])
            .with_exec(["ruff", "check", "src/"])
            .stdout()
        )

    @function
    async def sbom(
        self,
        source: Annotated[dagger.Directory, Doc("Python backend source directory")],
    ) -> dagger.File:
        """Generate a CycloneDX SBOM for vulnerability tracking.

        Produces a Software Bill of Materials in CycloneDX JSON format,
        suitable for upload to Dependency-Track or similar platforms.
        """
        return (
            self._base_container(source)
            .with_exec(["pip", "install", "cyclonedx-bom"])
            .with_exec([
                "cyclonedx-py", "requirements",
                "--input", "requirements.txt",
                "--output", "/app/sbom.json",
                "--format", "json",
            ])
            .file("/app/sbom.json")
        )
