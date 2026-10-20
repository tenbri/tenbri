import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { ThemeProvider } from "next-themes"

import App from "@/App"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import "@/index.css"
import mascot from "@/assets/mascot.webp?inline"

document.head.append(Object.assign(document.createElement("link"), { rel: "icon", href: mascot }))

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <TooltipProvider>
        <App />
        <Toaster richColors />
      </TooltipProvider>
    </ThemeProvider>
  </StrictMode>,
)
