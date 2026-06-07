import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, "..", "");
  const frontendHost = process.env.FRONTEND_HOST ?? env.FRONTEND_HOST ?? "127.0.0.1";
  const frontendPort = Number(process.env.FRONTEND_PORT ?? env.FRONTEND_PORT ?? 5173);
  const previewPort = Number(
    process.env.FRONTEND_PREVIEW_PORT ?? env.FRONTEND_PREVIEW_PORT ?? frontendPort,
  );

  return {
    envDir: "..",
    plugins: [react()],
    server: {
      host: frontendHost,
      port: frontendPort,
    },
    preview: {
      host: frontendHost,
      port: previewPort,
    },
  };
});
