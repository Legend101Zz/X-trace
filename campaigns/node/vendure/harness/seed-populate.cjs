// Harness script: replicates the populate step of `@vendure/create --ci` (create-vendure-app.ts
// ~L535-580) against the PostgreSQL configured through DB_* env, because the create tool's own
// postgres path starts a docker-compose database on the host and cannot run inside the build container.
const path = require("node:path");
const { populate } = require("@vendure/core/cli/populate");
const { bootstrap, DefaultLogger, LogLevel, JobQueueService } = require("@vendure/core");
const { config } = require("./vendure-config");

const assets = process.env.CREATE_ASSETS_DIR; // assets/ of the pinned @vendure/create tarball

const bootstrapFn = async () => {
  const app = await bootstrap({
    ...config,
    apiOptions: { ...(config.apiOptions ?? {}), port: 3000 },
    dbConnectionOptions: { ...config.dbConnectionOptions, synchronize: true },
    logger: new DefaultLogger({ level: LogLevel.Error }),
    importExportOptions: { importAssetsDir: path.join(assets, "images") },
  });
  await app.get(JobQueueService).start();
  return app;
};

populate(bootstrapFn, path.join(assets, "initial-data.json"), path.join(assets, "products.csv"))
  .then(async (app) => {
    await new Promise((r) => setTimeout(r, 20000)); // let the search-index jobs finish (create uses a fixed pause too)
    await app.close();
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
