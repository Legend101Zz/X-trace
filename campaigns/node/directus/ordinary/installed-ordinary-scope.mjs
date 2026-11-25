// Explicit scope for the installed ordinary-development lane. Full campaign remains separate.
export const ORDINARY_IDS = Object.freeze([
  "auth-anonymous-denied", "auth-invalid-login", "auth-admin-login", "item-create-read-db",
  "item-validation-null-required", "item-update-persists", "concurrent-writes-and-reads", "item-delete-then-gone",
]);

export function ordinaryScenarios(scenarios) {
  if (scenarios.length !== ORDINARY_IDS.length) throw new Error("ordinary_scenario_inventory");
  return ORDINARY_IDS.map((id) => {
    const rows = scenarios.filter((scenario) => scenario.id === id);
    if (rows.length !== 1) throw new Error("ordinary_scenario_inventory");
    return rows[0];
  });
}

const exact = new Set([
  "GET /users/me", "GET /users/me?fields=email,status,role.name", "GET /items/directus_users",
  "POST /auth/login", "POST /collections", "POST /items/xtrace_campaign_items",
]);

export function ordinaryRequest(method, route) {
  return typeof route === "string" && (exact.has(method + " " + route)
    || (method === "GET" || method === "PATCH" || method === "DELETE")
      && /^\/items\/xtrace_campaign_items\/[1-9][0-9]{0,15}$/.test(route));
}
