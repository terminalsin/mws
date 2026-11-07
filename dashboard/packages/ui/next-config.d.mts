import type { NextConfig } from "next";

export declare const zones: { id: string; title: string; basePath: string; port: number }[];
export declare function zoneUrl(id: string): string;
export declare function zoneConfig(id: string, extra?: NextConfig): NextConfig;
