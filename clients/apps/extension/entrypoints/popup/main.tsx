import React from "react";
import { createRoot } from "react-dom/client";
import { configureApi } from "@passwd/api-client";
import { App } from "./App";
import "./style.css";

// Point the shared client at the backend host (declared in host_permissions).
// For production, swap this for the deployed API origin.
configureApi({ baseUrl: "http://localhost:8080" });

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
