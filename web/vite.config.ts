import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built SPA is embedded into the Go binary and served from the same origin
// as the API, so requests to /api are relative. In dev, proxy them to the
// running wafportal admin server.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:9090",
    },
  },
});
