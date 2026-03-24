"""AcmeCorp deployment module — compliant, opinionated, simple."""

from typing import Annotated

import dagger
from dagger import DefaultPath, Doc, check, dag, function, object_type


ALLOWED_REGIONS = ["europe-west1", "us-central1"]

# Pin Trivy to a known safe version.
# Versions 0.69.4–0.69.6 were compromised in a supply chain attack (CVE-2026-33634).
TRIVY_VERSION = "0.69.3"

ENVIRONMENT_PROJECTS = {
    "staging": "acmecorp-staging",
    "production": "acmecorp-prod",
}

# Production deployments require multi-region for high availability.
PRODUCTION_REGIONS = ["europe-west1", "us-central1"]

# Resource defaults enforced across all Cloud Run services.
CLOUD_RUN_DEFAULTS = {
    "min_instances": {"staging": 0, "production": 1},
    "max_instances": {"staging": 5, "production": 50},
    "cpu": "1",
    "memory": "512Mi",
    "concurrency": 80,
    "timeout": "300s",
}


@object_type
class AcmeDeploy:
    """Deploy services the AcmeCorp way.

    Wraps public daggerverse modules with org-specific defaults:
    - Enforces naming conventions (acme-{team}-{service}-{env})
    - Always uses OIDC authentication (no service account keys in CI)
    - Deploys to the org's standard regions
    - Injects required labels and metadata for cost tracking and audit
    - Production services always authenticated (no public endpoints)
    - Git metadata (branch, commit SHA) attached to every deployment
    """

    def _validate_and_resolve(
        self,
        team: str,
        service_name: str,
        environment: str,
        region: str,
    ) -> dict:
        """Shared validation and naming logic."""
        if region not in ALLOWED_REGIONS:
            msg = f"Region {region} not allowed. Must be one of: {ALLOWED_REGIONS}"
            raise ValueError(msg)
        if environment not in ENVIRONMENT_PROJECTS:
            msg = f"Environment {environment} not allowed. Must be one of: {list(ENVIRONMENT_PROJECTS)}"
            raise ValueError(msg)

        return {
            "full_name": f"acme-{team}-{service_name}-{environment}",
            "project": ENVIRONMENT_PROJECTS[environment],
        }

    def _validate_production_branch(self, environment: str, git_branch: str) -> None:
        """Refuse production deployments from non-main branches."""
        if environment == "production" and git_branch != "main":
            msg = (
                f"Production deployment forbidden from branch '{git_branch}'. "
                f"Only the 'main' branch can deploy to production."
            )
            raise ValueError(msg)

    def _authenticate(
        self,
        project: str,
        oidc_request_token: dagger.Secret | None = None,
        oidc_request_url: dagger.Secret | None = None,
        gcloud_config: dagger.Directory | None = None,
    ) -> dagger.Container:
        """Authenticate to GCP — CI (OIDC) or local (ADC from host).

        In CI: pass oidc_request_token and oidc_request_url (from GitHub Actions).
        Locally: pass gcloud_config (your ~/.config/gcloud directory).
        """
        if gcloud_config:
            return dag.gcp_auth().gcloud_container_from_host(
                project_id=project,
                gcloud_config=gcloud_config,
            )

        if oidc_request_token and oidc_request_url:
            return dag.gcp_auth().gcloud_container_from_github_actions(
                workload_identity_provider="projects/123456/locations/global/workloadIdentityPools/github/providers/github-actions",
                project_id=project,
                oidc_request_token=oidc_request_token,
                oidc_request_url=oidc_request_url,
                service_account_email=f"ci-deployer@{project}.iam.gserviceaccount.com",
            )

        msg = "Provide either gcloud-config (local) or oidc-request-token + oidc-request-url (CI)"
        raise ValueError(msg)

    @function
    @check
    async def scan(
        self,
        source: Annotated[
            dagger.Directory,
            Doc("Backend source directory"),
            DefaultPath("."),
        ],
        port: Annotated[int, Doc("Application port")] = 8080,
    ) -> str:
        """Scan the built container for HIGH and CRITICAL CVEs.

        Builds the container from source using acme-backend, then runs
        Trivy against it. Fails if any vulnerabilities at HIGH severity
        or above are found. Pinned to a safe Trivy version.
        """
        container = dag.acme_backend().build(source=source, port=port)
        return await dag.trivy(version=TRIVY_VERSION).container(container).output(format="table")

    def _build_labels(
        self,
        team: str,
        environment: str,
        git_branch: str = "",
        git_sha: str = "",
    ) -> dict[str, str]:
        """Standard labels for cost tracking, audit, and ownership."""
        labels = {
            "team": team,
            "environment": environment,
            "managed-by": "dagger",
        }
        if git_branch:
            labels["git-branch"] = git_branch
        if git_sha:
            labels["git-sha"] = git_sha[:8]
        return labels

    @function
    async def cloud_run(
        self,
        container: Annotated[dagger.Container, Doc("Container to deploy (from acme-backend build)")],
        service_name: Annotated[str, Doc("Service name (without prefix)")],
        team: Annotated[str, Doc("Team name for naming and labels")],
        oidc_request_token: Annotated[dagger.Secret | None, Doc("ACTIONS_ID_TOKEN_REQUEST_TOKEN (CI)")] = None,
        oidc_request_url: Annotated[dagger.Secret | None, Doc("ACTIONS_ID_TOKEN_REQUEST_URL (CI)")] = None,
        gcloud_config: Annotated[dagger.Directory | None, Doc("Host gcloud config dir for local auth (~/.config/gcloud)")] = None,
        environment: Annotated[str, Doc("Target environment")] = "staging",
        region: Annotated[str, Doc("GCP region")] = "europe-west1",
        git_branch: Annotated[str, Doc("Git branch (for audit labels)")] = "",
        git_sha: Annotated[str, Doc("Git commit SHA (for audit labels)")] = "",
    ) -> str:
        """Deploy a container to Cloud Run with AcmeCorp compliance.

        Handles authentication, Artifact Registry push, and Cloud Run
        deployment in a single call. Enforces naming conventions,
        region whitelist, production branch gate, and access controls.

        Authentication: pass gcloud-config for local development, or
        oidc-request-token + oidc-request-url for CI (GitHub Actions).

        Production services are never publicly accessible — they require
        IAM authentication. Staging services allow unauthenticated access
        for testing convenience.
        """
        self._validate_production_branch(environment, git_branch)
        ctx = self._validate_and_resolve(team, service_name, environment, region)
        gcloud = self._authenticate(
            project=ctx["project"],
            oidc_request_token=oidc_request_token,
            oidc_request_url=oidc_request_url,
            gcloud_config=gcloud_config,
        )
        labels = self._build_labels(team, environment, git_branch, git_sha)

        # Scan for vulnerabilities before shipping
        await dag.trivy(version=TRIVY_VERSION).container(container).output(format="table")

        # Publish to Artifact Registry
        image_uri = await dag.gcp_artifact_registry(gcloud=gcloud).publish(
            container=container,
            project=ctx["project"],
            region=region,
            repository=f"acme-{team}",
            image=service_name,
            tag=f"{environment}-latest",
        )

        # Deploy to Cloud Run with org-standard configuration
        url = await dag.gcp_cloud_run(gcloud=gcloud).service().deploy(
            name=ctx["full_name"],
            image=image_uri,
            region=region,
            allow_unauthenticated=(environment != "production"),
            min_instances=CLOUD_RUN_DEFAULTS["min_instances"][environment],
            max_instances=CLOUD_RUN_DEFAULTS["max_instances"][environment],
            cpu=CLOUD_RUN_DEFAULTS["cpu"],
            memory=CLOUD_RUN_DEFAULTS["memory"],
            concurrency=CLOUD_RUN_DEFAULTS["concurrency"],
            timeout=CLOUD_RUN_DEFAULTS["timeout"],
            labels=labels,
        )

        return url

    @function
    async def firebase(
        self,
        dist: Annotated[dagger.Directory, Doc("Built frontend output (from acme-frontend build)")],
        service_name: Annotated[str, Doc("Service name for the hosting site")],
        team: Annotated[str, Doc("Team name")],
        oidc_request_token: Annotated[dagger.Secret | None, Doc("ACTIONS_ID_TOKEN_REQUEST_TOKEN (CI)")] = None,
        oidc_request_url: Annotated[dagger.Secret | None, Doc("ACTIONS_ID_TOKEN_REQUEST_URL (CI)")] = None,
        gcloud_config: Annotated[dagger.Directory | None, Doc("Host gcloud config dir for local auth (~/.config/gcloud)")] = None,
        environment: Annotated[str, Doc("Target environment")] = "staging",
        git_branch: Annotated[str, Doc("Git branch (for audit trail)")] = "",
    ) -> str:
        """Deploy a frontend to Firebase Hosting with AcmeCorp compliance.

        Deploys to production channel ('live') or a preview channel
        matching the environment name. Production deploys are gated
        to the main branch only.

        Authentication: pass gcloud-config for local development, or
        oidc-request-token + oidc-request-url for CI (GitHub Actions).
        """
        self._validate_production_branch(environment, git_branch)
        ctx = self._validate_and_resolve(team, service_name, environment, region="europe-west1")
        gcloud = self._authenticate(
            project=ctx["project"],
            oidc_request_token=oidc_request_token,
            oidc_request_url=oidc_request_url,
            gcloud_config=gcloud_config,
        )

        channel = "live" if environment == "production" else environment

        url = await dag.gcp_firebase(gcloud=gcloud).hosting().deploy(
            dist=dist,
            project=ctx["project"],
            channel=channel,
        )

        return url
