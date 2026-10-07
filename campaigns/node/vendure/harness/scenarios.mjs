// Vendure v3.7.3 baseline scenarios over the HTTP Shop/Admin API endpoints.
// Per ADR 0005 these exercise the HTTP + Nest seams only; GraphQL operations are NOT
// enumerated or asserted as product claims. Synthetic data only.

const errs = (j) => ({ errorCodes: (j?.errors || []).map((e) => e?.extensions?.code ?? "ERR") });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function vendureScenarios({ sql, admin }) {
  const state = {};
  const ADMIN = "/admin-api";
  const SHOP = "/shop-api";

  // gql: records one HTTP POST to the API endpoint; `label` names the operation for humans only.
  const gql = (http, label, api, query, variables, { token, project } = {}) =>
    http.call(label, "POST", api, {
      route: api,
      token,
      body: { query, variables: variables || {} },
      project: project || ((j) => ({ data: j?.data, ...errs(j) })),
    });

  const LOGIN = "mutation($u:String!,$p:String!){login(username:$u,password:$p){__typename ... on CurrentUser{identifier} ... on ErrorResult{errorCode}}}";
  const CREATE = "mutation($i:CreateProductInput!){createProduct(input:$i){id name slug enabled}}";
  const READ = "query($id:ID!){product(id:$id){id name slug}}";
  const product = (name, slug) => ({ enabled: true, translations: [{ languageCode: "en", name, slug, description: "Synthetic local test" }] });
  const dbProducts = () => sql("select pt.slug as slug, pt.name as name from product_translation pt where pt.slug like 'xtrace-%' order by pt.slug");

  return [
    {
      id: "auth-anonymous-admin-denied",
      name: "admin API query without a session is denied (FORBIDDEN)",
      kind: "auth",
      async run({ http }) {
        const r = await gql(http, "products (anonymous admin)", ADMIN, "{products(options:{take:1}){totalItems}}");
        return { assertions: { noData: !r.json?.data?.products, forbidden: (r.json?.errors || []).some((e) => e?.extensions?.code === "FORBIDDEN") } };
      },
    },
    {
      id: "auth-invalid-login",
      name: "invalid credentials rejected with InvalidCredentialsError",
      kind: "validation-error",
      async run({ http }) {
        const r = await gql(http, "login wrong password", ADMIN, LOGIN, { u: admin.identifier, p: "invalid-synthetic-password" });
        return { assertions: { invalid: r.json?.data?.login?.__typename === "InvalidCredentialsError" } };
      },
    },
    {
      id: "auth-admin-login",
      name: "synthetic superadmin logs in; bearer token issued; identity query works",
      kind: "auth",
      async run({ http }) {
        const r = await http.call("login", "POST", ADMIN, {
          route: ADMIN,
          body: { query: LOGIN, variables: { u: admin.identifier, p: admin.password } },
          project: (j) => ({ type: j?.data?.login?.__typename }),
        });
        state.token = r.headers?.get("vendure-auth-token") || null;
        const me = await gql(http, "me", ADMIN, "{me{identifier}}", {}, { token: state.token, project: (j) => ({ identifierMatches: j?.data?.me?.identifier === admin.identifier }) });
        return { assertions: { loggedIn: r.json?.data?.login?.__typename === "CurrentUser" && !!state.token, identity: me.json?.data?.me?.identifier === admin.identifier } };
      },
    },
    {
      id: "product-create-read-db",
      name: "create product, read it back, verify database row",
      kind: "business-db-write-read",
      async run({ http }) {
        const c = await gql(http, "create product", ADMIN, CREATE, { i: product("Xtrace Baseline", "xtrace-baseline") }, { token: state.token, project: (j) => ({ name: j?.data?.createProduct?.name, slug: j?.data?.createProduct?.slug, ...errs(j) }) });
        state.productId = c.json?.data?.createProduct?.id;
        const r = await gql(http, "read product", ADMIN, READ, { id: state.productId }, { token: state.token, project: (j) => ({ name: j?.data?.product?.name }) });
        return {
          assertions: { created: !!state.productId, readMatches: r.json?.data?.product?.name === "Xtrace Baseline" },
          db: { products: dbProducts() },
        };
      },
    },
    {
      id: "product-validation-invalid-language",
      name: "invalid translation language rejected; nothing written",
      kind: "validation-error",
      async run({ http }) {
        const before = dbProducts().length;
        const r = await gql(http, "create product invalid languageCode", ADMIN, CREATE, { i: { translations: [{ languageCode: "invalid", name: "Xtrace invalid", slug: "xtrace-invalid" }] } }, { token: state.token });
        return { assertions: { rejected: !!r.json?.errors?.length && !r.json?.data?.createProduct, nothingWritten: dbProducts().length === before }, db: { products: dbProducts() } };
      },
    },
    {
      id: "product-update-persists",
      name: "update product name; next read and DB row reflect it",
      kind: "business-db-write-read",
      async run({ http }) {
        const u = await gql(http, "update product", ADMIN, "mutation($i:UpdateProductInput!){updateProduct(input:$i){id name}}", { i: { id: state.productId, translations: [{ languageCode: "en", name: "Xtrace Updated" }] } }, { token: state.token, project: (j) => ({ name: j?.data?.updateProduct?.name }) });
        const r = await gql(http, "read product", ADMIN, READ, { id: state.productId }, { token: state.token, project: (j) => ({ name: j?.data?.product?.name }) });
        return { assertions: { updated: u.json?.data?.updateProduct?.name === "Xtrace Updated", readReflects: r.json?.data?.product?.name === "Xtrace Updated" }, db: { products: dbProducts() } };
      },
    },
    {
      id: "shop-order-flow",
      name: "anonymous shopper builds an order (add, adjust) and hits an expected state-transition error",
      kind: "business-multi-step",
      async run({ http }) {
        const list = await gql(http, "shop products", SHOP, "{products(options:{take:1}){items{id variants{id}}}}", {}, { project: (j) => ({ hasItems: (j?.data?.products?.items || []).length > 0 }) });
        const variantId = list.json?.data?.products?.items?.[0]?.variants?.[0]?.id;
        const add = await http.call("add item to order", "POST", SHOP, {
          route: SHOP,
          body: { query: "mutation($v:ID!,$q:Int!){addItemToOrder(productVariantId:$v,quantity:$q){__typename ... on Order{totalQuantity state lines{id quantity}} ... on ErrorResult{errorCode}}}", variables: { v: variantId, q: 2 } },
          project: (j) => ({ type: j?.data?.addItemToOrder?.__typename, totalQuantity: j?.data?.addItemToOrder?.totalQuantity, state: j?.data?.addItemToOrder?.state, lineQty: (j?.data?.addItemToOrder?.lines || []).map((l) => l.quantity) }),
        });
        const shopToken = add.headers?.get("vendure-auth-token");
        const lineId = add.json?.data?.addItemToOrder?.lines?.[0]?.id;
        const adj = await gql(http, "adjust order line", SHOP, "mutation($l:ID!,$q:Int!){adjustOrderLine(orderLineId:$l,quantity:$q){__typename ... on Order{totalQuantity}}}", { l: lineId, q: 3 }, { token: shopToken, project: (j) => ({ type: j?.data?.adjustOrderLine?.__typename, totalQuantity: j?.data?.adjustOrderLine?.totalQuantity }) });
        const bad = await gql(http, "transition without customer", SHOP, 'mutation{transitionOrderToState(state:"ArrangingPayment"){__typename ... on ErrorResult{errorCode}}}', {}, { token: shopToken, project: (j) => ({ type: j?.data?.transitionOrderToState?.__typename }) });
        const lines = sql("select quantity from order_line order by quantity");
        return {
          assertions: {
            shopSessionToken: !!shopToken,
            added: add.json?.data?.addItemToOrder?.__typename === "Order" && add.json.data.addItemToOrder.totalQuantity === 2,
            adjusted: adj.json?.data?.adjustOrderLine?.totalQuantity === 3,
            transitionRefused: bad.json?.data?.transitionOrderToState?.__typename === "OrderStateTransitionError",
          },
          db: { orderLines: lines },
        };
      },
    },
    {
      id: "worker-search-index-job",
      name: "created product becomes searchable only after the separate worker process completes its search-index jobs",
      kind: "async-worker",
      async run({ http }) {
        const c = await gql(http, "create searchable product", ADMIN, CREATE, { i: product("Xtrace Indexed Widget", "xtrace-indexed-widget") }, { token: state.token, project: (j) => ({ name: j?.data?.createProduct?.name }) });
        // The search index holds one entry per enabled variant, so the product needs a variant.
        const v = await gql(http, "create variant", ADMIN, "mutation($i:[CreateProductVariantInput!]!){createProductVariants(input:$i){id sku}}", {
          i: [{ productId: c.json?.data?.createProduct?.id, sku: "xtrace-indexed-widget-1", price: 1000, stockOnHand: 5, translations: [{ languageCode: "en", name: "Xtrace Indexed Widget" }] }],
        }, { token: state.token, project: (j) => ({ sku: j?.data?.createProductVariants?.[0]?.sku, ...errs(j) }) });
        let found = false;
        let attempts = 0;
        for (; attempts < 60 && !found; attempts++) {
          const s = await http.call("shop search (poll)", "POST", SHOP, {
            route: SHOP,
            body: { query: 'query{search(input:{term:"Indexed Widget",groupByProduct:true}){totalItems}}' },
            project: () => ({ polled: true }),
          });
          found = (s.json?.data?.search?.totalItems || 0) >= 1;
          if (!found) await sleep(500);
        }
        // poll attempts vary run to run; keep only the first and the last call in the fingerprint
        const calls = http.calls;
        const kept = calls.filter((x, i) => i === 0 || i >= calls.length - 1);
        http.calls.splice(0, http.calls.length, ...kept);
        // The stock server process does not run the job queue; only the separate worker does. Wait for the
        // worker to drain the update-search-index queue and assert every such job COMPLETED.
        let states = [];
        for (let i = 0; i < 60; i++) {
          states = sql(`select "state" as state, count(*)::int as n from job_record where "queueName"='update-search-index' group by "state" order by "state"`);
          if (states.length && states.every((r) => r.state === "COMPLETED")) break;
          await sleep(500);
        }
        const jobsDone = states.length > 0 && states.every((r) => r.state === "COMPLETED");
        return { assertions: { workerCompletedIndexJobs: jobsDone, created: c.status === 200 && !!c.json?.data?.createProduct?.id, variantCreated: v.json?.data?.createProductVariants?.[0]?.sku === "xtrace-indexed-widget-1", searchableViaJobQueue: found }, facts: { attempts }, db: { products: dbProducts(), indexJobStates: [...new Set(states.map((r) => r.state))] } };
      },
    },
    {
      id: "concurrent-writes-and-reads",
      name: "concurrent product creates, then concurrent reads each match their own record",
      kind: "concurrent",
      async run({ http }) {
        const names = Array.from({ length: 6 }, (_, i) => `Xtrace Conc ${i + 1}`);
        const created = await Promise.all(
          names.map((n) =>
            gql(http, `concurrent create ${n}`, ADMIN, CREATE, { i: product(n, n.toLowerCase().replace(/\s+/g, "-")) }, { token: state.token, project: (j) => ({ name: j?.data?.createProduct?.name, ...errs(j) }) }),
          ),
        );
        const ids = created.map((c) => c.json?.data?.createProduct?.id);
        const reads = await Promise.all(
          ids.flatMap((id, i) =>
            [0, 1, 2].map((rep) => gql(http, `concurrent read ${names[i]} #${rep}`, ADMIN, READ, { id }, { token: state.token, project: (j) => ({ name: j?.data?.product?.name }) })),
          ),
        );
        const own = reads.every((r, k) => r.json?.data?.product?.name === names[Math.floor(k / 3)]);
        http.calls.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
        return { assertions: { allCreated: ids.every(Boolean), distinctIds: new Set(ids).size === 6, everyReadMatchesOwnRecord: own }, db: { products: dbProducts() } };
      },
    },
    {
      id: "product-delete-then-gone",
      name: "delete product; reading it afterwards returns null",
      kind: "business-db-write-read",
      async run({ http }) {
        const d = await gql(http, "delete product", ADMIN, "mutation($id:ID!){deleteProduct(id:$id){result}}", { id: state.productId }, { token: state.token, project: (j) => ({ result: j?.data?.deleteProduct?.result }) });
        const r = await gql(http, "read deleted product", ADMIN, READ, { id: state.productId }, { token: state.token, project: (j) => ({ product: j?.data?.product ?? null }) });
        return { assertions: { deleted: d.json?.data?.deleteProduct?.result === "DELETED", gone: r.json?.data?.product === null }, db: { products: dbProducts() } };
      },
    },
    {
      id: "error-malformed-and-unknown",
      name: "malformed GraphQL request rejected and unknown route returns 404",
      kind: "error-path",
      async run({ http }) {
        const bad = await http.call("syntactically invalid query", "POST", SHOP, { route: SHOP, body: { query: "{ products(" }, project: errs });
        const nf = await http.call("GET unknown route", "GET", "/xtrace-no-such-route", { route: "/{unknown}", project: () => ({}) });
        return { assertions: { badRequest: bad.status >= 400 && bad.status < 500, notFound: nf.status === 404 } };
      },
    },
  ];
}
