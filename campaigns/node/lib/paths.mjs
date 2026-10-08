// Private (untracked) locations. Set XTRACE_CAMP_NODE_ROOT to the directory holding
// <project>/upstream (checkouts) and <project>/baseline-<n>/ (private results).
import os from "node:os";
import path from "node:path";

export const CAMPAIGN_ROOT = process.env.XTRACE_CAMP_NODE_ROOT || path.join(os.homedir(), ".cache", "xtrace", "campaigns", "node");
export const projectRoot = (project) => path.join(CAMPAIGN_ROOT, project);
export const IMAGE = (nodeVersion) => `xtrace-camp-node:${nodeVersion}`;
