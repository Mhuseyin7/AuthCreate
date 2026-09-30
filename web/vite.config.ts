import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({ plugins: [react(), tailwindcss()], server: { proxy: { "/admin": "http://localhost:8080", "/.well-known": "http://localhost:8080" } } });
