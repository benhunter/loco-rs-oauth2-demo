import React from "react";
import ReactDOM from "react-dom/client";
import { LocoSplash } from "./LocoSplash";
import { Login } from "./login";

import "./index.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("No root element found");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <Login />
  </React.StrictMode>,
);
