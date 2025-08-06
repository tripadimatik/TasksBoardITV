import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { readFileSync, existsSync } from "fs";
import { componentTagger } from "lovable-tagger";
import type { ServerOptions } from "vite";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const serverConfig: ServerOptions = {
    host: "::",
    port: 3000,
    allowedHosts: true,
  };

  return {
    server: serverConfig,
    build: {
      target: ["es2015", "chrome58", "firefox57", "safari11"], // Поддержка старых браузеров
      modulePreload: {
        polyfill: true,
      },
      cssCodeSplit: false,
    },
    esbuild: {
      target: "es2015", // Совместимость с мобильными браузерами
    },
    plugins: [react(), mode === "development" && componentTagger()].filter(
      Boolean,
    ),
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  };
});
