import express from "express";
import { chromium } from "playwright";
import dns from "node:dns/promises";
import net from "node:net";

const PORT = Number(process.env.PORT ?? 8080);
const RENDERER_SHARED_SECRET = process.env.RENDERER_SHARED_SECRET ?? "";
const MAX_CONCURRENT_RENDERS = Math.max(1, Number(process.env.MAX_CONCURRENT_RENDERS ?? 2));
const RENDER_TIMEOUT_MS = Math.max(5000, Number(process.env.RENDER_TIMEOUT_MS ?? 45000));

if (!RENDERER_SHARED_SECRET) {
  throw new Error("RENDERER_SHARED_SECRET must be configured");
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "40mb" }));

const browserPromise = chromium.launch({
  headless: true,
  args: ["--disable-dev-shm-usage"],
});

let activeRenders = 0;
const waiters = [];

function releaseSlot() {
  activeRenders = Math.max(0, activeRenders - 1);
  const next = waiters.shift();
  if (next) next();
}

async function acquireSlot() {
  if (activeRenders < MAX_CONCURRENT_RENDERS) {
    activeRenders += 1;
    return;
  }
  await new Promise((resolve) => waiters.push(resolve));
  activeRenders += 1;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  const normalized = ip.toLowerCase();
  if (normalized === "::1" || normalized === "::") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80:")) return true;
  return false;
}

async function isSafePublicHttpUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (!["http:", "https:"].includes(parsed.protocol)) return false;
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname === "localhost" || hostname.endsWith(".local")) return false;

  if (net.isIP(hostname)) return !isPrivateIp(hostname);

  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!records.length) return false;
    return records.every((record) => !isPrivateIp(record.address));
  } catch {
    return false;
  }
}

function authorized(req) {
  const auth = req.get("authorization") ?? "";
  return auth === `Bearer ${RENDERER_SHARED_SECRET}`;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, activeRenders, maxConcurrentRenders: MAX_CONCURRENT_RENDERS });
});

app.post("/render", async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { html, width, height } = req.body ?? {};
  if (typeof html !== "string" || html.length < 20) {
    return res.status(400).json({ error: "Missing or invalid html" });
  }
  if (!Number.isInteger(width) || !Number.isInteger(height)) {
    return res.status(400).json({ error: "width and height must be integers" });
  }
  if (width < 320 || width > 3840 || height < 320 || height > 3840) {
    return res.status(400).json({ error: "Unsupported render dimensions" });
  }

  await acquireSlot();
  let page;

  try {
    const browser = await browserPromise;
    const context = await browser.newContext({
      viewport: { width, height },
      deviceScaleFactor: 1,
      javaScriptEnabled: true,
    });

    page = await context.newPage();
    page.setDefaultTimeout(RENDER_TIMEOUT_MS);
    page.setDefaultNavigationTimeout(RENDER_TIMEOUT_MS);

    await page.route("**/*", async (route) => {
      const url = route.request().url();
      if (url.startsWith("data:") || url.startsWith("blob:") || url === "about:blank") {
        return route.continue();
      }
      if (await isSafePublicHttpUrl(url)) return route.continue();
      return route.abort("blockedbyclient");
    });

    await page.setContent(html, {
      waitUntil: "load",
      timeout: RENDER_TIMEOUT_MS,
    });

    // Wait for all fonts, images and the v12 auto-fit script to settle.
    await page.evaluate(async () => {
      if (document.fonts?.ready) {
        try { await document.fonts.ready; } catch {}
      }
      const images = Array.from(document.images);
      await Promise.all(images.map(async (img) => {
        if (!img.complete) {
          await new Promise((resolve) => {
            const done = () => resolve(undefined);
            img.addEventListener("load", done, { once: true });
            img.addEventListener("error", done, { once: true });
          });
        }
        if (typeof img.decode === "function") {
          try { await img.decode(); } catch {}
        }
      }));
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      await new Promise((resolve) => setTimeout(resolve, 60));
    });

    const root = page.locator(".flyer-root");
    if ((await root.count()) !== 1) {
      throw new Error("Expected exactly one .flyer-root element");
    }

    const overflow = await page.evaluate(() => {
      const selectors = [
        ".flyer-badge",
        ".brand-wordmark",
        ".flyer-eyebrow",
        ".flyer-headline",
        ".flyer-subheadline",
        ".flyer-cta",
        ".footer-label",
        ".footer-phone",
        ".footer-message",
      ];
      return selectors.flatMap((selector) => {
        const el = document.querySelector(selector);
        if (!el) return [];
        const widthOverflow = el.scrollWidth > el.clientWidth + 6;
        const heightOverflow = el.scrollHeight > el.clientHeight + 6;
        return widthOverflow || heightOverflow
          ? [{ selector, scrollWidth: el.scrollWidth, clientWidth: el.clientWidth, scrollHeight: el.scrollHeight, clientHeight: el.clientHeight }]
          : [];
      });
    });

    if (overflow.length) {
      console.error("Render rejected because text still overflows", overflow);
      return res.status(422).json({ error: "Flyer layout overflow detected", overflow });
    }

    const png = await root.screenshot({
      type: "png",
      animations: "disabled",
      caret: "hide",
      scale: "css",
      timeout: RENDER_TIMEOUT_MS,
    });

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Content-Length", String(png.length));
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(png);
  } catch (error) {
    console.error("[renderer] render failed", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: error instanceof Error ? error.message : "Render failed" });
    }
  } finally {
    try { await page?.context().close(); } catch {}
    releaseSlot();
  }
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Biz-BoT flyer renderer listening on :${PORT}`);
});

async function shutdown(signal) {
  console.log(`Received ${signal}; shutting down`);
  server.close(async () => {
    try {
      const browser = await browserPromise;
      await browser.close();
    } catch {}
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
