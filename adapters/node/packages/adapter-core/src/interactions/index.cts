export * from "./redact.cjs";
export {
  installPgCapture,
  pgPatchStatus,
  instrumentPgModule,
  instrumentPgClient,
  instrumentPgPool,
  type InteractionPatchHooks,
  type PgPatchStatus,
} from "./pg.cjs";
export {
  installMysqlCapture,
  mysqlPatchStatus,
  instrumentMysqlModule,
  instrumentMysqlConnection,
  type MysqlDriverName,
  type MysqlPatchStatus,
} from "./mysql.cjs";
export {
  installHttpClientCapture,
  httpClientPatchStatus,
  instrumentUndiciModule,
  type HttpClientPatchStatus,
} from "./http-client.cjs";

import { installHttpClientCapture } from "./http-client.cjs";
import { installMysqlCapture } from "./mysql.cjs";
import { installPgCapture, type InteractionPatchHooks } from "./pg.cjs";

/** Installs all database (`pg`, `mysql`/`mysql2`) and outbound HTTP interaction captures. */
export function installInteractionsCapture(hooks: InteractionPatchHooks): void {
  installPgCapture(hooks);
  installMysqlCapture(hooks);
  installHttpClientCapture(hooks);
}
