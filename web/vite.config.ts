import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Build configuration.
 *
 * The security-relevant settings here are the ones about what ends up on disk
 * and what the browser is allowed to reach.
 */
export default defineConfig({
  plugins: [react()],

  build: {
    // No source maps in the shipped bundle. They are a full-fidelity copy of the
    // source, including comments describing which fields are withheld and why,
    // served unauthenticated from the same origin as the app.
    sourcemap: false,
    target: "es2022",
    rollupOptions: {
      output: {
        // Content-hashed filenames so the app can be served with a long cache
        // while API responses stay no-store. Static code is cacheable;
        // intelligence data is not, and the two must not share a policy.
        entryFileNames: "assets/[name].[hash].js",
        chunkFileNames: "assets/[name].[hash].js",
        assetFileNames: "assets/[name].[hash].[ext]",
      },
    },
  },

  server: {
    // Dev proxy to the API. The app makes same-origin requests in every
    // environment, so `connect-src 'self'` in the CSP holds in development too —
    // a CSP that only applies in production is a CSP that is first tested in
    // production.
    proxy: {
      "/api": {
        target: process.env.CNA_API_ORIGIN ?? "http://127.0.0.1:8000",
        changeOrigin: false,
      },
    },
  },

  // The workstation uses system fonts and does not make external font requests.
  publicDir: "public",

  define: {
    // Nothing sensitive. Anything in `define` is inlined into the bundle in
    // plaintext, which makes it public regardless of what it is named.
    __BUILD_ID__: JSON.stringify(process.env.CNA_BUILD_ID ?? "dev"),
  },
});
