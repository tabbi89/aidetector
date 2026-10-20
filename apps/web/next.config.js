/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The containerized dev server and host-side `npm run build` share this
  // mounted directory; a build overwrites .next and corrupts the running
  // dev server. Compose points dev at its own distDir (see docker-compose).
  distDir: process.env.NEXT_DIST_DIR || ".next",
};

module.exports = nextConfig;
