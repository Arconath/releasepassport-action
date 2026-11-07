# ReleasePassport Vision QA Action

Run approved web QA missions against an independently verified GitHub deployment. Configure the repository, environment, ownership proof and trusted workflow in ReleasePassport, then use the generated workflow with an immutable Action commit pin.

The Action exchanges the job’s GitHub OIDC identity for a short-lived deployment-scoped session. Grant the QA job `contents: read` and `id-token: write`. Run it from the configured workflow on `main`; use `workflow_run` after a successful same-repository deployment workflow, or a manual dispatch. Do not check out pull-request code with testing-account secrets. The job checks out `${{ github.workflow_sha }}` with credential persistence disabled. Supply either a GitHub deployment ID or its target commit SHA; an optional preview URL must match the independently verified deployment origin.

## Automatic testing-account login

An optional committed `.mjs` module exports `default async function({page,baseURL})`. It signs into the verified application using explicitly selected `RP_TEST_*` environment variables from your own CI secrets and waits for an authenticated page. Set `auth-setup-script` to its relative path and `auth-env` to the selected variable names. Arconath credentials and AI keys are never needed by this Action.

Commit an exact Playwright development dependency and its lockfile at your repository root. Install dependencies from that lockfile with lifecycle scripts disabled, then run `./node_modules/.bin/playwright install --with-deps chromium` before invoking this Action. Generated workflows support npm and pnpm. Monorepos and generated dependencies need reviewed trusted preparation. Use a fresh checkout: tracked symlinks, submodules and `.gitattributes` are rejected. This checkout check attests tracked source bytes; it does not sandbox trusted setup code or attest untracked dependencies.

Login runs in a bounded child process with explicitly selected testing credentials; its logs are suppressed. Only the verified origin’s supported Secure host cookies and local storage are exported into an expiring session. Temporary state is private and cleaned up. Interactive MFA and unsupported authentication need an application-specific test-login flow; this Action does not bypass them.

## Results and limits

`status` is `passed` only when every admitted mission passes. `run-ids` contains the admitted run IDs. Failed, uncertain, cancelled and timed-out outcomes fail the Action. The total polling deadline is bounded to 900 seconds. Non-idempotent requests are not automatically retried. Ordinary ReleasePassport gates, quotas, private evidence and AI spending limits still apply; this helper does not grant extra usage.

## Development

Requires Node 24. Run `npm ci --ignore-scripts`, `./node_modules/.bin/playwright install chromium`, and `npm test`. Tests use synthetic HTTP/browser fixtures and never invoke paid AI. The maintained source is independently tested before an immutable commit is configured in ReleasePassport.
