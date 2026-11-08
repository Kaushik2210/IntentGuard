"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import type { Verdict } from "@/lib/data";
import { VERDICT_WORD } from "@/lib/data";

export function Icon({ v }: { v: Verdict }) {
  const common = { viewBox: "0 0 16 16", "aria-hidden": true, fill: "none", stroke: "currentColor", strokeWidth: 2.2, strokeLinecap: "round", strokeLinejoin: "round" } as const;
  if (v === "ALLOW") return <svg {...common}><path d="M3 8.5l3.2 3.2L13 4.8" /></svg>;
  if (v === "REVIEW") return <svg {...common}><circle cx="8" cy="8" r="6" /><path d="M8 4.8V8.4l2.2 1.4" /></svg>;
  if (v === "BLOCK") return <svg {...common}><circle cx="8" cy="8" r="6" /><path d="M4 12L12 4" /></svg>;
  return <svg {...common}><rect x="3" y="7" width="10" height="6.5" rx="1.5" /><path d="M5.2 7V5.2a2.8 2.8 0 015.6 0V7" /></svg>;
}

export function VerdictPill({ v }: { v: Verdict }) {
  return (
    <span className={`pill ${v}`}>
      <Icon v={v} />
      {VERDICT_WORD[v]}
    </span>
  );
}

/** Fades children in when they scroll into view. */
export function Reveal({ children, className = "", delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const node = ref.current;
    if (!node || typeof IntersectionObserver === "undefined") {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (es) => {
        if (es.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);
  return (
    <div ref={ref} className={`rv ${seen ? "in" : ""} ${className}`} style={{ transitionDelay: `${delay}ms` }}>
      {children}
    </div>
  );
}

/** Subtle 3D tilt toward the pointer. Disabled for touch and reduced motion. */
export function Tilt({ children, className = "", max = 4 }: { children: ReactNode; className?: string; max?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const on = useRef(true);
  useEffect(() => {
    on.current = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);
  return (
    <div
      ref={ref}
      className={`tilt ${className}`}
      onPointerMove={(e) => {
        const n = ref.current;
        if (!n || !on.current || e.pointerType === "touch") return;
        const r = n.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - 0.5;
        const y = (e.clientY - r.top) / r.height - 0.5;
        n.style.transform = `perspective(1100px) rotateY(${(x * max).toFixed(2)}deg) rotateX(${(-y * max).toFixed(2)}deg)`;
      }}
      onPointerLeave={() => {
        if (ref.current) ref.current.style.transform = "";
      }}
    >
      {children}
    </div>
  );
}

export function Window({ title, children, badge }: { title: string; children: ReactNode; badge?: ReactNode }) {
  return (
    <div className="window">
      <div className="chrome">
        <span className="dot r" />
        <span className="dot y" />
        <span className="dot g" />
        <span className="title">{title}</span>
        {badge}
      </div>
      {children}
    </div>
  );
}

export function CopyButton({ text }: { text: string }) {
  const [label, setLabel] = useState("Copy");
  return (
    <button
      type="button"
      className="btn sm"
      onClick={() => {
        navigator.clipboard
          .writeText(text)
          .then(() => setLabel("Copied"))
          .catch(() => setLabel("Select and copy"))
          .finally(() => setTimeout(() => setLabel("Copy"), 1600));
      }}
    >
      {label}
    </button>
  );
}
