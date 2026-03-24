"""AcmeCorp Angular frontend builder — standardized builds and testing."""

from typing import Annotated

import dagger
from dagger import DefaultPath, Doc, check, dag, function, object_type


# Approved Node.js base image — pinned to LTS for security compliance.
APPROVED_BASE_IMAGE = "node:20-slim"


@object_type
class AcmeFrontend:
    """Build and test Angular frontends the AcmeCorp way.

    Enforces:
    - Organization-approved Node.js version (20 LTS)
    - Standardized npm cache volumes
    - Production build configuration with source map exclusion
    - Vitest-based testing via Angular's built-in test runner
    - Audit check for known vulnerabilities in dependencies
    """

    def _base_container(self, source: dagger.Directory) -> dagger.Container:
        """Standard Node container with source and cached deps."""
        return (
            dag.container()
            .from_(APPROVED_BASE_IMAGE)
            .with_workdir("/app")
            .with_directory("/app", source)
            .with_mounted_cache("/root/.npm", dag.cache_volume("acme-npm"))
            .with_exec(["npm", "ci"])
        )

    @function
    def build(
        self,
        source: Annotated[dagger.Directory, Doc("Angular project source directory")],
    ) -> dagger.Directory:
        """Build the Angular app for production.

        Returns a Directory containing the dist/ output,
        ready to be passed to acme-deploy for Firebase Hosting.
        """
        return (
            dag.angular()
            .with_base(APPROVED_BASE_IMAGE)
            .with_npm_cache(dag.cache_volume("acme-npm"))
            .build(source=source, configuration="production")
        )

    @function
    @check
    async def test(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Angular project source directory"),
            DefaultPath("."),
        ],
    ) -> str:
        """Run the Angular test suite."""
        return await (
            self._base_container(source)
            .with_exec(["npx", "ng", "test"])
            .stdout()
        )

    @function
    @check
    async def lint(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Angular project source directory"),
            DefaultPath("."),
        ],
    ) -> str:
        """Run Angular linting."""
        return await (
            self._base_container(source)
            .with_exec(["npx", "ng", "lint"])
            .stdout()
        )

    @function
    @check
    async def audit(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Angular project source directory"),
            DefaultPath("."),
        ],
    ) -> str:
        """Check npm dependencies for known vulnerabilities.

        Runs npm audit at the 'moderate' severity level. Fails if any
        vulnerabilities at moderate or higher are found.
        """
        return await (
            self._base_container(source)
            .with_exec(["npm", "audit", "--audit-level=moderate"])
            .stdout()
        )
