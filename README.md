# X-trace

X-trace helps you answer **“What happened inside my backend when this request arrived?”** It records how your application handles HTTP requests during local development. Pick an endpoint, open a recording, and follow the calls through your source in a browser or terminal.

For example, when a developer submits the edit-owner form in Spring Petclinic, they can reopen that request and inspect the handler, the calls beneath it, and the outcome X-trace captured. A line is highlighted only when the recording contains an event for that line. Missing source, redacted values, and incomplete recordings are labeled so you can see where the evidence ends.

## Release status

**0.0.1 is in development.** The project calls this first public release **v0.01** in its roadmap. As of November 19, 2026, there is no published package or selected release candidate. All 55 mandatory requirements still need formal acceptance. [Release tracker](https://github.com/Legend101Zz/X-trace/issues/1) · [Acceptance ledger](evidence/v0.01/requirements.json) · [Releases](https://github.com/Legend101Zz/X-trace/releases)

| Area | What works today | Work remaining for 0.0.1 |
| --- | --- | --- |
| Java recording | A packaged build captured Spring MVC requests in Petclinic. Replay checks covered source identity, executed lines, frame values, and reopening a recording. | Reliable capture through shutdown, broader Java framework coverage, and verification across supported launch and attach configurations. |
| Node.js recording | The adapter implements Node HTTP and Express instrumentation. | Fastify, NestJS, authored TypeScript sources, and linking work across workers and child processes still need release evidence. |
| Replay and export | The Petclinic campaign exercised both browser views, the terminal viewer, and local exports. OpenAPI describes routes, Postman produces a collection, cURL produces command recipes, and the developer bundle collects the exports with a manifest. | Catalog conflicts and history, export accuracy when scopes share a route, and replay accessibility and performance remain open. |
| Distribution | Linux CI builds and checks development packages. | The release requires six real-application campaigns, fresh installs on Linux x86_64 and macOS arm64, and usability sessions with developers. |

The latest **Petclinic campaign** passed 37 of 45 checks on commit `7448048`. The other eight recorded limitations, including how load and overhead were measured. On the subsequent `main` commit `be441c5`, the JDK 21 / Node 24 Linux configuration passed all 23 release checks. The JDK 17 / Node 22 configuration and the main unit and integration job failed. [Petclinic results](https://github.com/Legend101Zz/X-trace/actions/runs/43201696564) · [CI results for that commit](https://github.com/Legend101Zz/X-trace/actions/runs/43214553598) · [Current CI](https://github.com/Legend101Zz/X-trace/actions/workflows/ci.yml?query=branch%3Amain)

## Explore from source

From an X-trace checkout with Rust and a C compiler installed, these commands show the available commands and capture options.

```sh
cargo run --locked -p xtrace-cli --bin xtrace -- --help
cargo run --locked -p xtrace-cli --bin xtrace -- run --help
```

If you already have an initialized project with recordings, point the CLI at **that application's repository**. The first command lists its recordings. The second starts the local viewer and prints a short-lived, single-use URL. Open it in your browser and keep the command running while you explore.

```sh
project_dir="/absolute/path/to/your/recorded-project"
cargo run --locked -p xtrace-cli --bin xtrace -- recording list --project-dir "$project_dir"
cargo run --locked -p xtrace-cli --bin xtrace -- open --project-dir "$project_dir" --viewer --no-browser
```

Recordings stay in the local X-trace data directory. The application repository holds a project pointer at `.xtrace/config.toml`. Treat the viewer URL as a temporary credential. For a first capture, the developer setup includes the Java agent build and a worked Spring example. [Spring capture walkthrough](docs/development/setup.md#experimental-xtrace-run) · [Local security model](docs/security-local.md)

## Project documentation

- [Product design](docs/plans/x-trace/01-product.md) explains the intended endpoint-to-source workflow.
- [Development tools](tools/dev/README.md) covers dependency setup, cache locations, and fast checks.
- [Release specification](docs/releases/v0.01.md) lists the framework, platform, and usability commitments for 0.0.1.
- [Documentation index](docs/INDEX.md) links the architecture, storage format, API, and design decisions.

X-trace uses the [MIT license](LICENSE).
