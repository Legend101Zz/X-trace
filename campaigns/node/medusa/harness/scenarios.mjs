// Medusa v2.21.2 (dtc-starter backend) baseline scenarios. Synthetic data only.
import { psqlRows } from "../../lib/stack.mjs";

const errShape = (j) => ({ type: j?.type, message: typeof j?.message === "string" ? j.message.replace(/\s+/g, " ").slice(0, 160) : undefined });
const prodShape = (p) => ({ title: p?.title, handle: p?.handle, status: p?.status, options: (p?.options || []).map((o) => o.title) });

export function medusaScenarios({ db, admin }) {
  const dbRows = () =>
    psqlRows(db.container, db.database, `select handle, title, status from product where deleted_at is null and handle like 'xtrace-%' order by handle`, db.user);
  const state = {};

  const createProduct = (http, token, label, suffix, extra = {}) =>
    http.call(label, "POST", "/admin/products", {
      route: "/admin/products",
      token,
      body: { title: `Xtrace ${suffix}`, handle: `xtrace-${suffix.toLowerCase().replace(/\W+/g, "-")}`, status: "published", options: [{ title: "Size", values: ["One"] }], ...extra },
      project: (j) => ({ product: prodShape(j?.product) , ...(j?.type ? errShape(j) : {}) }),
    });

  return [
    {
      id: "auth-unauthorized-admin",
      name: "admin API without a token is rejected 401",
      kind: "auth",
      async run({ http }) {
        const r = await http.call("GET /admin/products anonymous", "GET", "/admin/products", { route: "/admin/products", project: errShape });
        const r2 = await http.call("GET /admin/users/me anonymous", "GET", "/admin/users/me", { route: "/admin/users/me", project: errShape });
        return { assertions: { products401: r.status === 401, me401: r2.status === 401 } };
      },
    },
    {
      id: "auth-invalid-login",
      name: "invalid credentials rejected 401",
      kind: "validation-error",
      async run({ http }) {
        const r = await http.call("login wrong password", "POST", "/auth/user/emailpass", {
          route: "/auth/user/emailpass",
          body: { email: admin.email, password: "invalid-synthetic-password" },
          project: (j) => ({ type: j?.type, message: j?.message }),
        });
        return { assertions: { status401: r.status === 401 } };
      },
    },
    {
      id: "auth-admin-login",
      name: "synthetic admin logs in and reads own identity",
      kind: "auth",
      async run({ http }) {
        const login = await http.call("login", "POST", "/auth/user/emailpass", {
          route: "/auth/user/emailpass",
          body: { email: admin.email, password: admin.password },
          project: (j) => ({ hasToken: typeof j?.token === "string" }),
        });
        state.token = login.json?.token || null;
        const me = await http.call("users/me", "GET", "/admin/users/me", {
          route: "/admin/users/me",
          token: state.token,
          project: (j) => ({ email: j?.user?.email }),
        });
        return { assertions: { loggedIn: login.status === 200 && !!state.token, identity: me.status === 200 && me.json?.user?.email === admin.email } };
      },
    },
    {
      id: "product-validation-strict",
      name: "unknown body field rejected (strict zod validation); nothing written",
      kind: "validation-error",
      async run({ http }) {
        const before = dbRows().length;
        const r = await http.call("create product with unknown field", "POST", "/admin/products", {
          route: "/admin/products",
          token: state.token,
          body: { title: "Xtrace invalid", handle: "xtrace-invalid", unsupported_baseline_field: true },
          project: errShape,
        });
        return { assertions: { rejected4xx: r.status >= 400 && r.status < 500, noRowWritten: dbRows().length === before }, db: { rows: dbRows() } };
      },
    },
    {
      id: "product-create-read-db",
      name: "create product, list/get it, verify database row",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const created = await createProduct(http, t, "create product", "Persisted");
        const id = created.json?.product?.id;
        state.productId = id;
        const got = await http.call("get product", "GET", `/admin/products/${id}`, { route: "/admin/products/{id}", token: t, project: (j) => ({ product: prodShape(j?.product) }) });
        const listed = await http.call("list products", "GET", "/admin/products?limit=100&fields=id,handle", {
          route: "/admin/products",
          token: t,
          project: (j) => ({ handles: (j?.products || []).map((p) => p.handle).sort(), count: j?.count }),
        });
        return {
          assertions: {
            created: created.status === 200 && typeof id === "string",
            getMatches: got.status === 200 && got.json?.product?.handle === "xtrace-persisted",
            listedContains: listed.status === 200 && (listed.json?.products || []).some((p) => p.id === id),
          },
          db: { rows: dbRows() },
        };
      },
    },
    {
      id: "product-update-persists",
      name: "update product title; next read and DB row reflect it",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const upd = await http.call("update product", "POST", `/admin/products/${state.productId}`, {
          route: "/admin/products/{id}",
          token: t,
          body: { title: "Xtrace Persisted Updated" },
          project: (j) => ({ product: prodShape(j?.product) }),
        });
        const got = await http.call("get product", "GET", `/admin/products/${state.productId}`, { route: "/admin/products/{id}", token: t, project: (j) => ({ product: prodShape(j?.product) }) });
        return { assertions: { updated: upd.status === 200, readReflects: got.json?.product?.title === "Xtrace Persisted Updated" }, db: { rows: dbRows() } };
      },
    },
    {
      id: "storefront-publishable-key-flow",
      name: "sales channel + publishable key + published product visible through the Store API",
      kind: "business-multi-module",
      async run({ http }) {
        const t = state.token;
        const noKey = await http.call("store products without publishable key", "GET", "/store/products", { route: "/store/products", project: errShape });
        const sc = await http.call("create sales channel", "POST", "/admin/sales-channels", {
          route: "/admin/sales-channels",
          token: t,
          body: { name: "Xtrace Channel", description: "synthetic" },
          project: (j) => ({ name: j?.sales_channel?.name }),
        });
        const scId = sc.json?.sales_channel?.id;
        const key = await http.call("create publishable key", "POST", "/admin/api-keys", {
          route: "/admin/api-keys",
          token: t,
          body: { title: "Xtrace key", type: "publishable" },
          project: (j) => ({ type: j?.api_key?.type, title: j?.api_key?.title }),
        });
        const keyId = key.json?.api_key?.id;
        const token = key.json?.api_key?.token;
        const link = await http.call("link key to channel", "POST", `/admin/api-keys/${keyId}/sales-channels`, {
          route: "/admin/api-keys/{id}/sales-channels",
          token: t,
          body: { add: [scId] },
          project: (j) => ({ ok: !!j?.api_key }),
        });
        const prod = await createProduct(http, t, "create product in channel", "Storefront", { sales_channels: [{ id: scId }] });
        const store = await http.call("store products with key", "GET", "/store/products?fields=handle,title", {
          route: "/store/products",
          headers: { "x-publishable-api-key": token },
          project: (j) => ({ handles: (j?.products || []).map((p) => p.handle).sort(), count: j?.count }),
        });
        return {
          assertions: {
            noKeyRejected: noKey.status === 400,
            channelCreated: sc.status === 200 && !!scId,
            keyCreated: key.status === 200 && !!token,
            linked: link.status === 200,
            productCreated: prod.status === 200,
            storeSeesProduct: store.status === 200 && (store.json?.products || []).some((p) => p.handle === "xtrace-storefront"),
          },
          db: { rows: dbRows() },
        };
      },
    },
    {
      id: "concurrent-writes-and-reads",
      name: "concurrent product creates, then concurrent reads each match their own record",
      kind: "concurrent",
      async run({ http }) {
        const t = state.token;
        const suffixes = Array.from({ length: 6 }, (_, i) => `Conc${i + 1}`);
        const created = await Promise.all(suffixes.map((s) => createProduct(http, t, `concurrent create ${s}`, s)));
        const ids = created.map((c) => c.json?.product?.id);
        const reads = await Promise.all(
          ids.flatMap((id, i) =>
            [0, 1, 2].map((rep) =>
              http.call(`concurrent get ${suffixes[i]} #${rep}`, "GET", `/admin/products/${id}`, { route: "/admin/products/{id}", token: t, project: (j) => ({ product: prodShape(j?.product) }) }),
            ),
          ),
        );
        const own = reads.every((r, k) => r.status === 200 && r.json?.product?.handle === `xtrace-${suffixes[Math.floor(k / 3)].toLowerCase()}`);
        http.calls.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
        return { assertions: { allCreated: created.every((c) => c.status === 200), distinctIds: new Set(ids).size === 6, everyReadMatchesOwnRecord: own }, db: { rows: dbRows() } };
      },
    },
    {
      id: "product-delete-then-gone",
      name: "delete product; get afterwards returns 404; row soft-deleted",
      kind: "business-db-write-read",
      async run({ http }) {
        const t = state.token;
        const del = await http.call("delete product", "DELETE", `/admin/products/${state.productId}`, { route: "/admin/products/{id}", token: t, project: (j) => ({ deleted: j?.deleted, object: j?.object }) });
        const got = await http.call("get deleted product", "GET", `/admin/products/${state.productId}`, { route: "/admin/products/{id}", token: t, project: errShape });
        return { assertions: { deleted: del.status === 200 && del.json?.deleted === true, gone: got.status === 404 }, db: { rows: dbRows() } };
      },
    },
    {
      id: "error-unknown-route",
      name: "unknown route 404 and malformed JSON body rejected",
      kind: "error-path",
      async run({ http }) {
        const nf = await http.call("GET unknown route", "GET", "/xtrace-no-such-route", { route: "/{unknown}", project: errShape });
        const bad = await http.call("malformed JSON body", "POST", "/auth/user/emailpass", { route: "/auth/user/emailpass", body: "{not json", project: errShape });
        return { assertions: { notFound: nf.status === 404, malformedRejected: bad.status >= 400 && bad.status < 500 } };
      },
    },
  ];
}
