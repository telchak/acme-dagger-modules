# AcmeCorp Private Dagger Modules

Private, opinionated Dagger modules that wrap public [daggerverse](https://daggerverse.dev/) modules with AcmeCorp's organizational standards: Python version policy, Node version policy, cache conventions, security scanning, and GCP deployment compliance.

This repository is a companion to **Part 3** of the [Dagger CI/CD blog series](https://github.com/telchak/dagger-ci-demo): *From Scripts to a Platform: Your CI/CD Module Library*.

## Modules

| Module | Description | Wraps |
|--------|-------------|-------|
| `acme-backend` | Python backend builder — standardized, cached, production-ready | [`python-build`](https://github.com/telchak/daggerverse/tree/main/python-build) |
| `acme-frontend` | Angular frontend builder — standardized builds and testing | [`angular`](https://github.com/telchak/daggerverse/tree/main/angular) |
| `acme-deploy` | Deployment to GCP (Cloud Run + Firebase) with security scanning | [`gcp-auth`](https://github.com/telchak/daggerverse/tree/main/gcp-auth), [`gcp-artifact-registry`](https://github.com/telchak/daggerverse/tree/main/gcp-artifact-registry), [`gcp-cloud-run`](https://github.com/telchak/daggerverse/tree/main/gcp-cloud-run), [`gcp-firebase`](https://github.com/telchak/daggerverse/tree/main/gcp-firebase), [`trivy`](https://daggerverse.dev/mod/github.com/sagikazarmark/daggerverse/trivy) |
| `tests` | Integration tests for all three modules above | — |

## Usage

```bash
# Build the backend
dagger call -m acme-backend build --source=./backend

# Build and test the frontend
dagger call -m acme-frontend test --source=./frontend

# Deploy to Cloud Run
dagger call -m acme-deploy cloud-run \
  --backend-source=./backend \
  --project-id=my-gcp-project \
  --region=europe-west1
```

Or consume them as dependencies in your own Dagger module:

```json
{
  "dependencies": [
    { "name": "acme-backend", "source": "github.com/telchak/acme-dagger-modules/acme-backend@v1.0.0" },
    { "name": "acme-frontend", "source": "github.com/telchak/acme-dagger-modules/acme-frontend@v1.0.0" },
    { "name": "acme-deploy", "source": "github.com/telchak/acme-dagger-modules/acme-deploy@v1.0.0" }
  ]
}
```

## Architecture

```
acme-dagger-modules/
├── acme-backend/       # Python build, test, lint (wraps python-build)
├── acme-frontend/      # Angular build, test, lint (wraps angular)
├── acme-deploy/        # Cloud Run + Firebase deploy (wraps GCP modules + Trivy)
└── tests/              # Integration tests for all modules
```

The key idea: public daggerverse modules handle generic operations (build a Python project, deploy to Cloud Run). These private modules wrap them with organizational decisions — which Python version, which base image, which security scanner, which GCP project structure. Developers consume the private modules and get compliance for free.

## Related

- [Dagger CI/CD Blog Series](https://github.com/telchak/dagger-ci-demo) — the full 4-part series
- [telchak/daggerverse](https://github.com/telchak/daggerverse) — the public modules these private modules wrap
- [daggerverse.dev](https://daggerverse.dev/) — the public Dagger module registry

## License

Apache-2.0
