import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { viteSingleFile } from "vite-plugin-singlefile"

// One self-contained HTML file, embedded in tenbrid (crates/tenbri-server/src/ui/index.html).
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  build: { outDir: "../crates/tenbri-server/src/ui", emptyOutDir: true },
  server: { proxy: { "/v1": "http://127.0.0.1:7070" } },
})
