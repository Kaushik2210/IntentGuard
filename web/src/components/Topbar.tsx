"use client";

import { data } from "@/lib/data";

export default function Topbar() {
  const toggle = () => {
    const root = document.documentElement;
    const attr = root.getAttribute("data-theme");
    const light = attr ? attr === "light" : window.matchMedia("(prefers-color-scheme: light)").matches;
    const next = light ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try {
      localStorage.setItem("ig-theme", next);
    } catch {
      /* private mode: the theme just will not persist */
    }
  };
  return (
    <header className="topbar">
      <div className="wrap">
        <a className="brand" href="#top">
          <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7z" fill="var(--accent)" />
            <path d="M11 16l4 4 7-8" fill="none" stroke="var(--accent-ink)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          IntentGuard
        </a>
        <nav className="nav" aria-label="Page sections">
          <a href="#replay">Replay</a>
          <a href="#smuggle">Smuggle</a>
          <a href="#risk">Risk</a>
          <a href="#audit">Audit</a>
          <a href="#results">Results</a>
          <a href="#limits">Limits</a>
          <a href="#try">Try it</a>
          <a href={data.repo}>GitHub</a>
          <button type="button" onClick={toggle} aria-label="Switch between light and dark theme">Theme</button>
        </nav>
      </div>
    </header>
  );
}
