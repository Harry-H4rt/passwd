import React from "react";
import { createRoot } from "react-dom/client";
import { configureApi } from "@passwd/api-client";
import { App } from "./App";
import "./styles.css";

// Default "" = same-origin (dev proxy / co-hosted prod). Override with
// VITE_API_BASE for a separately-hosted API. See clients/apps/web/.env.example.
configureApi({ baseUrl: import.meta.env.VITE_API_BASE ?? "" });

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
