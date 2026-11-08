import type { NextConfig } from "next";

// The site is a static export served from GitHub Pages at /IntentGuard/. Set NEXT_BASE_PATH="" for a custom domain.
const basePath = process.env.NEXT_BASE_PATH ?? (process.env.NODE_ENV === "production" ? "/IntentGuard" : "");

const nextConfig: NextConfig = {
  output: "export",
  basePath,
  assetPrefix: basePath || undefined,
  images: { unoptimized: true },
  trailingSlash: true,
  reactStrictMode: true,
};

export default nextConfig;
