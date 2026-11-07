import type { NextConfig } from "next";
import { zoneConfig } from "@mws-dashboard/ui/next-config";

// Served under its base path; the shell rewrites that path to this server.
const config: NextConfig = zoneConfig("storage");

export default config;
