import type { Rule } from "@mws-dashboard/ui";
import { CreateApp, CreateBranch, StartDeployment } from "@mws-dashboard/ui/model/amplify";

// Amplify's model leaves branch names unconstrained; Git's rules decide.
export const BRANCH: Rule = { ...CreateBranch.branchName, format: "branch", generate: { prefix: "feature/" } };

export const APP_NAME: Rule = { ...CreateApp.name, generate: "name" };

export const SOURCE_URL: Rule = { ...StartDeployment.sourceUrl, hint: "An s3:// or https:// URL" };

export { CreateApp, CreateBranch };
