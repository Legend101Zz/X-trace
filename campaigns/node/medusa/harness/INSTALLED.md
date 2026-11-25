# Installed Medusa development proof

Refs #120, #8 and #6. The hosted Linux proof uses the immutable starter revision,
its frozen pnpm dependencies, Medusa's ordinary migrations, synthetic admin and
start command, pinned PostgreSQL settings, and the existing eleven commerce
scenarios. Each leg gets a fresh PostgreSQL container and synthetic credentials.
The Ubuntu runner uses the same pinned Node executable on both legs so the
Ubuntu-built X-trace archive runs natively. This differs from historical Docker
Bookworm application preparation. The HTTP service and database are reachable
only through host loopback on the disposable runner.

The first leg starts the normal server directly. The second starts it through the
public CLI in a freshly verified prefix and names the installed adapter
distribution. It uses the ordinary default observation policy, so the proof
expects explicit unmatched observations and an empty observed catalog. No source
or catalog association is inferred from registry source references.

The readiness request is persisted and separated before the workload when
observed. For readiness and each of the 46 commerce calls, the client verifies
the listening socket and the accepted loopback connection against the owned
Medusa process before writing HTTP bytes. It refuses every 3xx response without
following Location. Database observations use the immutable per-leg container
ID via the runner's local Docker socket. The installed viewer's listener is
verified against its own process. The accepted socket is verified before the
bootstrap credential or session cookie is sent on each viewer connection.

Each runtime leg has a fresh home and passes the telemetry disable settings.
Package and dependency preparation may access approved registries. The
ownership checks cover harness requests and do not attest every outbound action
of upstream dependencies.

The original runner checks all scenario own-checks and fingerprints
between the legs. Authenticated API and installed CLI read every bounded page
after the application stops, using the same recording IDs, terminal outcomes
and explicit persisted event fields. Aggregate response-status equality excludes
the readiness recording. The count of responses to the concurrent commerce
group comes from the HTTP workload. Individual and concurrent recording
attribution remain unverified, including when all aggregate counts agree.

Use the coordinator-reviewed private workflow for the actual hosted run.
All setup and application logs, bootstrap secrets, credentials, raw recordings,
scenario fingerprints, the unsigned archive and installation receipts stay in
owner-only runner storage. Only a finite stage/count/provenance report is
eligible for upload. The development proof does not establish broader privacy
qualification, restart/browser/overhead, current stable pin qualification or
release acceptance.
