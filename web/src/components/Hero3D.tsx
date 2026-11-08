"use client";

import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { allSteps, shortCall, VERDICT_WORD, type Step, type Verdict } from "@/lib/data";
import { Icon } from "./ui";

const COLOR: Record<Verdict, number> = { ALLOW: 0x38e0a0, REVIEW: 0xf6b93b, BLOCK: 0xff6464, QUARANTINE: 0xa193ff };
const CSS_COLOR: Record<Verdict, string> = { ALLOW: "#38e0a0", REVIEW: "#f6b93b", BLOCK: "#ff6464", QUARANTINE: "#a193ff" };
const SPEED = 3.4;
const GATE_X = -0.3;

function shieldShape(k: number): THREE.Shape {
  const s = new THREE.Shape();
  s.moveTo(0, 1.75 * k);
  s.lineTo(1.25 * k, 1.35 * k);
  s.lineTo(1.25 * k, 0.3 * k);
  s.bezierCurveTo(1.25 * k, -0.9 * k, 0.55 * k, -1.45 * k, 0, -1.78 * k);
  s.bezierCurveTo(-0.55 * k, -1.45 * k, -1.25 * k, -0.9 * k, -1.25 * k, 0.3 * k);
  s.lineTo(-1.25 * k, 1.35 * k);
  s.closePath();
  return s;
}

function ringGeometry(outer: number, inner: number, depth: number, bevel: boolean): THREE.ExtrudeGeometry {
  const shape = shieldShape(outer);
  shape.holes.push(new THREE.Path(shieldShape(inner).getPoints(32)));
  const g = new THREE.ExtrudeGeometry(shape, {
    depth,
    bevelEnabled: bevel,
    bevelThickness: bevel ? 0.05 : 0,
    bevelSize: bevel ? 0.05 : 0,
    bevelSegments: 4,
    curveSegments: 32,
  });
  g.translate(0, 0, -depth / 2);
  return g;
}

function labelTexture(text: string, dot: string): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = 680;
  c.height = 150;
  const g = c.getContext("2d")!;
  g.fillStyle = "rgba(9,13,21,0.9)";
  g.strokeStyle = "rgba(255,255,255,0.24)";
  g.lineWidth = 3;
  g.beginPath();
  g.roundRect(4, 4, 672, 142, 40);
  g.fill();
  g.stroke();
  g.fillStyle = dot;
  g.shadowColor = dot;
  g.shadowBlur = 14;
  g.beginPath();
  g.arc(52, 75, 13, 0, Math.PI * 2);
  g.fill();
  g.shadowBlur = 0;
  g.font = "600 36px ui-monospace, Menlo, Consolas, monospace";
  g.fillStyle = "#eef2f8";
  g.textBaseline = "middle";
  g.fillText(text, 86, 78, 570);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  return t;
}

function glowTexture(): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.35, "rgba(255,255,255,0.35)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(c);
}

type PState = "in" | "out" | "bounce" | "hold" | "freeze";
interface Packet {
  step: Step;
  group: THREE.Group;
  card: THREE.Mesh;
  glow: THREE.Sprite;
  crystal: THREE.Mesh | null;
  state: PState;
  t: number;
  vy: number;
  neutral: THREE.CanvasTexture;
  colored: THREE.CanvasTexture;
}

export default function Hero3D() {
  const mount = useRef<HTMLDivElement>(null);
  const [score, setScore] = useState({ passed: 0, stopped: 0 });
  const [mode, setMode] = useState<"live" | "still" | "none">("live");

  useEffect(() => {
    const host = mount.current;
    if (!host) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    } catch {
      setMode("none");
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    const canvas = renderer.domElement;
    canvas.setAttribute("role", "img");
    canvas.setAttribute(
      "aria-label",
      "3D animation: tool calls fly toward a steel and glass shield gate. Allowed calls pass through, harmful ones bounce back and shatter, risky ones wait for a person, and the worst freeze into crystal.",
    );
    host.appendChild(canvas);

    const scene = new THREE.Scene();
    const pm = new THREE.PMREMGenerator(renderer);
    const envTex = pm.fromScene(new RoomEnvironment(), 0.04).texture;
    scene.environment = envTex;
    const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 80);
    const lookAt = new THREE.Vector3(0.2, 0.1, 0);

    const disposables: { dispose: () => void }[] = [pm, envTex];
    const track = <T extends { dispose: () => void }>(o: T): T => {
      disposables.push(o);
      return o;
    };

    // gate: brushed steel frame, glass panel, glowing inner edge, scanning beam
    const gate = new THREE.Group();
    gate.rotation.y = Math.PI / 2;
    gate.position.x = GATE_X;
    const frameMat = track(new THREE.MeshPhysicalMaterial({ color: 0x9aa6ba, metalness: 1, roughness: 0.27, clearcoat: 0.6, clearcoatRoughness: 0.2, envMapIntensity: 1.2 }));
    const frame = new THREE.Mesh(track(ringGeometry(1.05, 0.82, 0.3, true)), frameMat);
    const edgeMat = track(new THREE.MeshBasicMaterial({ color: COLOR.ALLOW, toneMapped: false }));
    const edge = new THREE.Mesh(track(ringGeometry(0.825, 0.79, 0.08, false)), edgeMat);
    const glassMat = track(new THREE.MeshPhysicalMaterial({ color: 0xb4e2ff, metalness: 0, roughness: 0.05, transmission: 0.93, thickness: 0.5, ior: 1.35, transparent: true, side: THREE.DoubleSide, envMapIntensity: 1.3, attenuationColor: new THREE.Color(0x7ad0ff), attenuationDistance: 2.4 }));
    const glass = new THREE.Mesh(track(new THREE.ShapeGeometry(shieldShape(0.8), 32)), glassMat);
    const beamMat = track(new THREE.MeshBasicMaterial({ color: COLOR.ALLOW, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, toneMapped: false, depthWrite: false }));
    const beam = new THREE.Mesh(track(new THREE.PlaneGeometry(2.0, 0.03)), beamMat);
    gate.add(frame, edge, glass, beam);
    scene.add(gate);

    const floorMat = track(new THREE.MeshStandardMaterial({ color: 0x080b10, metalness: 0.85, roughness: 0.38 }));
    const floor = new THREE.Mesh(track(new THREE.PlaneGeometry(80, 80)), floorMat);
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -2.05;
    scene.add(floor);
    const grid = new THREE.GridHelper(80, 80, 0x2f4260, 0x18222f);
    grid.position.y = -2.04;
    const gridMat = grid.material as THREE.LineBasicMaterial;
    gridMat.transparent = true;
    gridMat.opacity = 0.5;
    track(grid.geometry);
    track(gridMat);
    scene.add(grid);

    scene.add(new THREE.HemisphereLight(0x8aa2c8, 0x0a0d12, 0.35));
    const key = new THREE.DirectionalLight(0xffffff, 2.1);
    key.position.set(4, 6, 5);
    scene.add(key);
    const rim = new THREE.PointLight(0x62adff, 18, 14);
    rim.position.set(-4, 2, -3);
    scene.add(rim);
    const gateLight = new THREE.PointLight(COLOR.ALLOW, 6, 9);
    gateLight.position.set(GATE_X, 0, 1.8);
    scene.add(gateLight);

    // theme: the page can be dark or light, the scene follows
    const applyTheme = () => {
      const attr = document.documentElement.getAttribute("data-theme");
      const light = attr ? attr === "light" : window.matchMedia("(prefers-color-scheme: light)").matches;
      const bg = light ? 0xeceff4 : 0x05070b;
      scene.fog = new THREE.Fog(bg, 11, 30);
      floorMat.color.set(light ? 0xd5dce8 : 0x080b10);
      gridMat.opacity = light ? 0.35 : 0.5;
      renderer.toneMappingExposure = light ? 0.95 : 1.05;
    };
    applyTheme();
    const themeObs = new MutationObserver(applyTheme);
    themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    // packets
    const steps = allSteps();
    const glowTex = track(glowTexture());
    const cardGeo = track(new THREE.PlaneGeometry(2.1, 0.46));
    const crystalGeo = track(new THREE.OctahedronGeometry(0.32));
    const labelCache = new Map<string, THREE.CanvasTexture>();
    const tex = (text: string, dot: string) => {
      const k = text + dot;
      let t = labelCache.get(k);
      if (!t) {
        t = labelTexture(text, dot);
        labelCache.set(k, t);
        disposables.push(t);
      }
      return t;
    };
    const packets: Packet[] = [];
    let qi = 0;
    const order = steps.map((_, i) => i).sort((a, b) => ((a * 7 + 3) % 11) - ((b * 7 + 3) % 11));
    const makePacket = (step: Step, x: number, y: number, z: number, state: PState): Packet => {
      const text = shortCall(step);
      const neutral = tex(text, "#8a95a8");
      const colored = tex(text, CSS_COLOR[step.verdict]);
      const mat = new THREE.MeshBasicMaterial({ map: state === "in" ? neutral : colored, transparent: true, depthWrite: false, toneMapped: false });
      const card = new THREE.Mesh(cardGeo, mat);
      const gm = new THREE.SpriteMaterial({ map: glowTex, color: COLOR[step.verdict], transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false, toneMapped: false });
      const glow = new THREE.Sprite(gm);
      glow.scale.set(3.2, 1.3, 1);
      const group = new THREE.Group();
      group.add(glow, card);
      group.position.set(x, y, z);
      scene.add(group);
      const p: Packet = { step, group, card, glow, crystal: null, state, t: 0, vy: 0, neutral, colored };
      packets.push(p);
      return p;
    };
    const dropPacket = (p: Packet) => {
      scene.remove(p.group);
      (p.card.material as THREE.Material).dispose();
      (p.glow.material as THREE.Material).dispose();
      if (p.crystal) (p.crystal.material as THREE.Material).dispose();
      packets.splice(packets.indexOf(p), 1);
    };
    const spawn = () => {
      const i = order[qi++ % order.length];
      const lane = ((qi * 53) % 5) - 2;
      makePacket(steps[i], -9, lane * 0.55 + (qi % 3) * 0.08, (((qi * 31) % 5) - 2) * 0.5, "in");
    };

    // shards and shock rings
    const SH = 200;
    const shardGeo = track(new THREE.TetrahedronGeometry(0.06));
    const shardMat = track(new THREE.MeshBasicMaterial({ toneMapped: false }));
    const shards = new THREE.InstancedMesh(shardGeo, shardMat, SH);
    shards.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    shards.frustumCulled = false;
    scene.add(shards);
    const sp = Array.from({ length: SH }, () => ({ p: new THREE.Vector3(0, -50, 0), v: new THREE.Vector3(), life: 0, s: 1, c: new THREE.Color() }));
    let sCursor = 0;
    const burst = (x: number, y: number, z: number, color: number, n: number) => {
      for (let i = 0; i < n; i++) {
        const s = sp[sCursor++ % SH];
        s.p.set(x, y, z);
        const a = Math.random() * Math.PI * 2;
        const v = 1.5 + Math.random() * 3.2;
        s.v.set((Math.random() - 0.5) * 2.4, Math.sin(a) * v + 1, Math.cos(a) * v);
        s.life = 1;
        s.s = 0.6 + Math.random() * 1.4;
        s.c.set(color);
      }
    };
    const rings: { mesh: THREE.Mesh; t: number }[] = [];
    const ringGeo = track(new THREE.RingGeometry(0.92, 1, 72));
    const addRing = (color: number) => {
      const m = new THREE.Mesh(ringGeo, new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, toneMapped: false, depthWrite: false }));
      m.rotation.y = Math.PI / 2;
      m.position.x = GATE_X;
      scene.add(m);
      rings.push({ mesh: m, t: 0 });
    };

    let passed = 0;
    let stopped = 0;
    let flash = 0;
    let flashColor = new THREE.Color(COLOR.ALLOW);
    const dummy = new THREE.Object3D();
    const stepPacket = (p: Packet, dt: number) => {
      p.t += dt;
      const g = p.group;
      const gm = p.glow.material as THREE.SpriteMaterial;
      const cm = p.card.material as THREE.MeshBasicMaterial;
      if (p.state === "in") {
        g.position.x += SPEED * dt;
        gm.opacity = 0.12;
        if (g.position.x >= GATE_X - 0.25) {
          const v = p.step.verdict;
          flash = 1;
          flashColor = new THREE.Color(COLOR[v]);
          addRing(COLOR[v]);
          cm.map = p.colored;
          cm.needsUpdate = true;
          if (v === "ALLOW") {
            p.state = "out";
            passed++;
          } else {
            stopped++;
            if (v === "BLOCK") {
              p.state = "bounce";
              burst(GATE_X, g.position.y, g.position.z, COLOR.BLOCK, 36);
            } else if (v === "REVIEW") {
              p.state = "hold";
              g.position.x = GATE_X - 0.6;
              p.t = 0;
            } else {
              p.state = "freeze";
              p.t = 0;
              p.crystal = new THREE.Mesh(crystalGeo, new THREE.MeshPhysicalMaterial({ color: 0xa193ff, metalness: 0, roughness: 0.08, transmission: 0.7, thickness: 0.6, ior: 1.5, emissive: 0x4a3aa8, emissiveIntensity: 0.6, envMapIntensity: 1.6 }));
              p.crystal.scale.set(2.4, 0.9, 0.9);
              g.add(p.crystal);
              p.card.visible = false;
            }
          }
          setScore({ passed, stopped });
        }
      } else if (p.state === "out") {
        g.position.x += SPEED * dt;
        g.position.y -= 0.05 * dt;
        gm.opacity = Math.max(0.35, 0.9 - p.t * 0.2);
        const s = Math.max(0.5, 1 - p.t * 0.09);
        g.scale.setScalar(s);
        if (g.position.x > 10) dropPacket(p);
      } else if (p.state === "bounce") {
        g.position.x -= SPEED * 1.2 * dt;
        g.position.y += 0.15 * dt;
        g.rotation.z += dt * 2.4;
        cm.opacity = Math.max(0, 1 - p.t * 0.85);
        gm.opacity = cm.opacity * 0.5;
        if (cm.opacity <= 0) dropPacket(p);
      } else if (p.state === "hold") {
        g.position.y += Math.sin(p.t * 4) * 0.002;
        gm.opacity = 0.5 + Math.sin(p.t * 6) * 0.25;
        if (p.t > 2.1) {
          p.state = "bounce";
          p.t = 0;
          burst(GATE_X, g.position.y, g.position.z, COLOR.REVIEW, 14);
        }
      } else {
        p.vy -= 8 * dt;
        g.position.y += p.vy * dt;
        g.position.x += 0.4 * dt;
        if (p.crystal) p.crystal.rotation.z += dt * 2;
        gm.opacity = 0.5;
        if (g.position.y < -1.8) {
          burst(g.position.x, -1.8, g.position.z, COLOR.QUARANTINE, 46);
          dropPacket(p);
        }
      }
    };

    let w = 1;
    let h = 1;
    const resize = () => {
      w = host.clientWidth || 1;
      h = host.clientHeight || 1;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      if (w > 900) camera.setViewOffset(w, h, -w * 0.2, 0, w, h);
      else camera.clearViewOffset();
      camera.updateProjectionMatrix();
      if (reduce) renderFrame(0);
    };

    let px = 0;
    let py = 0;
    let tpx = 0;
    let tpy = 0;
    const start = performance.now();
    const renderFrame = (t: number) => {
      px += (tpx - px) * 0.06;
      py += (tpy - py) * 0.06;
      camera.position.set(5.4 + px * 1.5 + Math.sin(t / 3400) * 0.25, 1.5 - py * 0.7, 7.6);
      camera.lookAt(lookAt);
      beam.position.y = Math.sin(t / 900) * 1.35;
      beam.position.z = 0;
      flash = Math.max(0, flash - 0.03);
      gateLight.intensity = 6 + flash * 60;
      gateLight.color.copy(flashColor);
      edgeMat.color.copy(flashColor.clone().lerp(new THREE.Color(COLOR.ALLOW), 1 - flash));
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i];
        r.t += 0.02;
        r.mesh.scale.setScalar(1 + r.t * 3.6);
        (r.mesh.material as THREE.MeshBasicMaterial).opacity = Math.max(0, 0.9 - r.t * 1.1);
        if (r.t > 0.9) {
          scene.remove(r.mesh);
          (r.mesh.material as THREE.Material).dispose();
          rings.splice(i, 1);
        }
      }
      for (const p of packets) {
        p.card.quaternion.copy(camera.quaternion);
        p.glow.quaternion.copy(camera.quaternion);
        if (p.crystal) p.crystal.quaternion.copy(camera.quaternion);
      }
      for (let i = 0; i < SH; i++) {
        const s = sp[i];
        if (s.life > 0) {
          s.v.y -= 6 * 0.016;
          s.p.addScaledVector(s.v, 0.016);
          s.life -= 0.016 * 1.1;
          if (s.p.y < -2) {
            s.p.y = -2;
            s.v.y *= -0.4;
          }
        }
        dummy.position.copy(s.p);
        dummy.scale.setScalar(s.life > 0 ? s.s * Math.min(1, s.life * 2) : 0);
        dummy.rotation.set(t / 300 + i, t / 400 + i, 0);
        dummy.updateMatrix();
        shards.setMatrixAt(i, dummy.matrix);
        shards.setColorAt(i, s.c);
      }
      shards.instanceMatrix.needsUpdate = true;
      if (shards.instanceColor) shards.instanceColor.needsUpdate = true;
      renderer.render(scene, camera);
    };

    let raf = 0;
    let last = performance.now();
    let spawnIn = 0;
    let visible = true;
    const loop = (now: number) => {
      raf = requestAnimationFrame(loop);
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (!visible || document.hidden) return;
      spawnIn -= dt;
      if (spawnIn <= 0) {
        spawn();
        spawnIn = 0.95;
      }
      for (const p of [...packets]) stepPacket(p, dt);
      renderFrame(now - start);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(host);
    let io: IntersectionObserver | null = null;
    const onMove = (e: PointerEvent) => {
      const r = host.getBoundingClientRect();
      tpx = (e.clientX - r.left) / r.width - 0.5;
      tpy = (e.clientY - r.top) / r.height - 0.5;
    };
    const onLeave = () => {
      tpx = 0;
      tpy = 0;
    };
    if (reduce) {
      setMode("still");
      steps.slice(0, 7).forEach((s, i) => {
        const p = makePacket(s, i % 2 ? 1.6 + i * 0.75 : -3.6 + i * 0.3, ((i % 3) - 1) * 0.6, ((i % 2) - 0.5) * 0.8, i % 2 ? "out" : "in");
        (p.glow.material as THREE.SpriteMaterial).opacity = 0.35;
      });
      renderFrame(0);
    } else {
      host.parentElement?.addEventListener("pointermove", onMove);
      host.parentElement?.addEventListener("pointerleave", onLeave);
      io = new IntersectionObserver((es) => {
        visible = es[0].isIntersecting;
      });
      io.observe(host);
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io?.disconnect();
      themeObs.disconnect();
      host.parentElement?.removeEventListener("pointermove", onMove);
      host.parentElement?.removeEventListener("pointerleave", onLeave);
      for (const p of [...packets]) dropPacket(p);
      for (const r of rings) (r.mesh.material as THREE.Material).dispose();
      disposables.forEach((d) => d.dispose());
      renderer.dispose();
      host.removeChild(canvas);
    };
  }, []);

  return (
    <>
      <div className="scene" ref={mount} data-testid="gate" />
      {mode === "none" && <div className="fallback3d">3D view unavailable on this device. Everything below still works.</div>}
      <p className="hint">{mode === "still" ? "Motion reduced: showing a still frame" : "Real engine decisions, in 3D. Move your pointer to look around."}</p>
      <div className="hud" aria-hidden="true">
        <div className="wrap">
          <div className="legend">
            {(["ALLOW", "REVIEW", "BLOCK", "QUARANTINE"] as Verdict[]).map((v) => (
              <span key={v} className={`pill ${v}`}>
                <Icon v={v} />
                {VERDICT_WORD[v]}
              </span>
            ))}
          </div>
          <div className="score">
            <span className="pill" data-testid="passed">passed {score.passed}</span>
            <span className="pill" data-testid="stopped">stopped {score.stopped}</span>
          </div>
        </div>
      </div>
    </>
  );
}
