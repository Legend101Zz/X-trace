// Harness-provided entrypoint (adaptation, no upstream file modified): same as the generated
// src/index.ts (runMigrations -> bootstrap) plus starting the job queue inside the server
// process. With SQLite, a separate worker process makes both processes write the same file and
// Vendure 3.7.3 fails with "SqliteError: database is locked" (observed in baseline attempts).
const { bootstrap, runMigrations, JobQueueService } = require("@vendure/core");
const { config } = require("./vendure-config");

runMigrations(config)
  .then(() => bootstrap(config))
  .then((app) => app.get(JobQueueService).start())
  .catch((err) => {
    console.log(err);
    process.exit(1);
  });
