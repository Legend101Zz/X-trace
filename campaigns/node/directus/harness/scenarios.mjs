// Directus v12.4.1 baseline scenarios. Synthetic data only; every scenario returns
// {assertions, db} and the runner derives the semanticEffectFingerprint.
import { psqlRows } from "../../lib/stack.mjs";

const COLLECTION = "xtrace_campaign_items";

const errCodes = (j) => ({ errorCodes: (j?.errors || []).map((e) => e?.extensions?.code) });

export function directusScenarios({ db, admin }) {
  const rows = () => psqlRows(db.container, db.database, `select name, quantity from ${COLLECTION} order by name, quantity`, db.user);
  const tableCount = () => Number(psqlRows(db.container, db.database, `select count(*) from ${COLLECTION}`, db.user)[0][0]);
  const state = { token: null };

  return [
    {
      id: "auth-anonymous-denied",
      name: "anonymous request to protected API is denied",
      kind: "auth",
      async run({ http }) {
        const me = await http.call("anonymous /users/me", "GET", "/users/me", { route: "/users/me", project: errCodes });
        const items = await http.call("anonymous /items", "GET", "/items/directus_users", { route: "/items/{collection}", project: errCodes });
        return { assertions: { meDenied: me.status === 401 || me.status === 403, itemsDenied: items.status === 401 || items.status === 403 } };
      },
    },
    {
      id: "auth-invalid-login",
      name: "invalid credentials rejected with INVALID_CREDENTIALS",
      kind: "validation-error",
      async run({ http }) {
        const r = await http.call("login wrong password", "POST", "/auth/login", {
          route: "/auth/login",
          body: { email: admin.email, password: "invalid-synthetic-password" },
          project: errCodes,
        });
        return { assertions: { status401: r.status === 401, code: r.json?.errors?.[0]?.extensions?.code === "INVALID_CREDENTIALS" } };
      },
    },
    {
      id: "auth-admin-login",
      name: "synthetic local admin authenticates and reads own identity",
      kind: "auth",
      async run({ http, norm }) {
        const login = await http.call("login", "POST", "/auth/login", {
          route: "/auth/login",
          body: { email: admin.email, password: admin.password },
          project: (j) => ({ hasAccessToken: typeof j?.data?.access_token === "string", hasRefresh: typeof j?.data?.refresh_token === "string" }),
        });
        state.token = login.json?.data?.access_token || null;
        const me = await http.call("users/me", "GET", "/users/me?fields=email,status,role.name", {
          route: "/users/me",
          token: state.token,
          project: (j) => ({ email: j?.data?.email, status: j?.data?.status, role: j?.data?.role?.name }),
        });
        return { assertions: { loggedIn: login.status === 200 && !!state.token, identity: me.status === 200 && me.json?.data?.email === admin.email } };
      },
    },
    {
      id: "item-create-read-db",
      name: "create collection and item, read it back, verify database row",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const coll = await http.call("create collection", "POST", "/collections", {
          route: "/collections",
          token: t,
          body: {
            collection: COLLECTION,
            schema: {},
            fields: [
              { field: "id", type: "integer", schema: { is_primary_key: true, has_auto_increment: true } },
              { field: "name", type: "string", schema: { is_nullable: false } },
              { field: "quantity", type: "integer", schema: { is_nullable: false } },
            ],
          },
          project: (j) => ({ collection: j?.data?.collection }),
        });
        const created = await http.call("create item", "POST", `/items/${COLLECTION}`, {
          route: "/items/{collection}",
          token: t,
          body: { name: "Synthetic item", quantity: 7 },
          project: (j) => ({ name: j?.data?.name, quantity: j?.data?.quantity }),
        });
        const id = created.json?.data?.id;
        const read = await http.call("read item", "GET", `/items/${COLLECTION}/${id}`, {
          route: "/items/{collection}/{id}",
          token: t,
          project: (j) => ({ name: j?.data?.name, quantity: j?.data?.quantity }),
        });
        state.firstId = id;
        return {
          assertions: {
            collectionCreated: coll.status === 200,
            itemCreated: created.status === 200 && Number.isInteger(id),
            readMatches: read.status === 200 && read.json?.data?.quantity === 7,
          },
          db: { rows: rows() },
        };
      },
    },
    {
      id: "item-validation-null-required",
      name: "null required field rejected and no row written",
      kind: "validation-error",
      async run({ http }) {
        const before = tableCount();
        const r = await http.call("create item with null name", "POST", `/items/${COLLECTION}`, {
          route: "/items/{collection}",
          token: state.token,
          body: { name: null, quantity: 1 },
          project: errCodes,
        });
        const after = tableCount();
        return { assertions: { rejected: r.status >= 400 && r.status < 500, noRowWritten: before === after }, db: { rowCountUnchanged: before === after } };
      },
    },
    {
      id: "item-update-persists",
      name: "update persists through the next database read",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const patch = await http.call("patch item", "PATCH", `/items/${COLLECTION}/${state.firstId}`, {
          route: "/items/{collection}/{id}",
          token: t,
          body: { quantity: 42 },
          project: (j) => ({ quantity: j?.data?.quantity }),
        });
        const read = await http.call("read item", "GET", `/items/${COLLECTION}/${state.firstId}`, {
          route: "/items/{collection}/{id}",
          token: t,
          project: (j) => ({ name: j?.data?.name, quantity: j?.data?.quantity }),
        });
        return { assertions: { patched: patch.status === 200, readUpdated: read.json?.data?.quantity === 42 }, db: { rows: rows() } };
      },
    },
    {
      id: "concurrent-writes-and-reads",
      name: "concurrent creates then concurrent reads each match their own record",
      kind: "concurrent",
      async run({ http }) {
        const t = state.token;
        const names = Array.from({ length: 6 }, (_, i) => `Concurrent ${i + 1}`);
        const created = await Promise.all(
          names.map((n, i) =>
            http.call(`concurrent create ${n}`, "POST", `/items/${COLLECTION}`, {
              route: "/items/{collection}",
              token: t,
              body: { name: n, quantity: 100 + i },
              project: (j) => ({ name: j?.data?.name, quantity: j?.data?.quantity }),
            }),
          ),
        );
        const ids = created.map((c) => c.json?.data?.id);
        const reads = await Promise.all(
          ids.flatMap((id, i) =>
            [0, 1, 2].map((rep) =>
              http.call(`concurrent read ${names[i]} #${rep}`, "GET", `/items/${COLLECTION}/${id}`, {
                route: "/items/{collection}/{id}",
                token: t,
                project: (j) => ({ name: j?.data?.name, quantity: j?.data?.quantity }),
              }),
            ),
          ),
        );
        const own = reads.every((r, k) => {
          const i = Math.floor(k / 3);
          return r.status === 200 && r.json?.data?.name === names[i] && r.json?.data?.quantity === 100 + i;
        });
        // Call order inside Promise.all is non-deterministic; sort the recorded calls by label.
        http.calls.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
        return {
          assertions: {
            allCreated: created.every((c) => c.status === 200),
            distinctIds: new Set(ids).size === 6,
            everyReadMatchesOwnRecord: own,
          },
          db: { rows: rows() },
        };
      },
    },
    {
      id: "item-delete-then-gone",
      name: "delete removes the item; reading it afterwards fails",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const del = await http.call("delete item", "DELETE", `/items/${COLLECTION}/${state.firstId}`, { route: "/items/{collection}/{id}", token: t });
        const read = await http.call("read deleted item", "GET", `/items/${COLLECTION}/${state.firstId}`, {
          route: "/items/{collection}/{id}",
          token: t,
          project: errCodes,
        });
        return { assertions: { deleted: del.status === 204, gone: read.status === 403 || read.status === 404 }, db: { rows: rows() } };
      },
    },
    {
      id: "error-unknown-route",
      name: "unknown route returns ROUTE_NOT_FOUND",
      kind: "error-path",
      async run({ http }) {
        const r = await http.call("GET unknown route", "GET", "/xtrace-no-such-route", { route: "/{unknown}", project: errCodes });
        const bad = await http.call("malformed JSON body", "POST", "/auth/login", { route: "/auth/login", body: "{not json", project: errCodes });
        return { assertions: { notFound: r.status === 404, malformedRejected: bad.status >= 400 && bad.status < 500 } };
      },
    },
  ];
}
