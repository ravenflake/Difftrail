import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { applyTheme, getStoredThemeMode, resolveTheme } from "./theme";
import "./styles.css";

applyTheme(resolveTheme(getStoredThemeMode()));

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
