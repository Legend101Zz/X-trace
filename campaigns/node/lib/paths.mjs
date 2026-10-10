// Private (untracked) locations. Set XTRACE_CAMP_NODE_ROOT to the directory holding
// <project>/upstream (checkouts) and <project>/baseline-<n>/ (private results).
import os from "node:os";
import path from "node:path";

export const CAMPAIGN_ROOT = process.env.XTRACE_CAMP_NODE_ROOT || path.join(os.homedir(), ".cache", "xtrace", "campaigns", "node");
export const projectRoot = (project) => path.join(CAMPAIGN_ROOT, project);
// The tag carries the platform when it is not the Mac default, so an x86_64 image never replaces the arm64 one of the same Node version.
export const IMAGE = (nodeVersion) => {
  const plat = process.env.XCAMP_PLATFORM || "linux/arm64";
  return plat === "linux/arm64" ? `xtrace-camp-node:${nodeVersion}` : `xtrace-camp-node:${nodeVersion}-${plat.split("/")[1]}`;
};
