import React from "react";
import { createRoot } from "react-dom/client";
import { configureApi } from "@passwd/api-client";
import { App } from "./App";
import "./style.css";

// Point the shared client at the backend host (declared in host_permissions).
// Override with WXT_API_BASE for production (see .env.example).
configureApi({
  baseUrl: (import.meta.env as Record<string, string | undefined>).WXT_API_BASE ?? "http://localhost:8080",
});

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
