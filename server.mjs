import express from "express";
import { chromium } from "playwright";
import dns from "node:dns/promises";
import net from "node:net";

/**
 * Biz-BoT Server PNG Renderer
 *
 * Version:
 * v13.1-autofit
 *
 * Changes:
 * - Server-side flyer PNG rendering with Playwright
 * - Final emergency text auto-fit
 * - Small Chromium font-metric tolerance
 * - Renderer version exposed through /health
 * - Renderer version logged for every render request
 * - External URL / SSRF protection
 * - Render concurrency protection
 */

const RENDERER_VERSION = "v13.1-autofit";

const PORT = Number(
  process.env.PORT ?? 8080,
);

const RENDERER_SHARED_SECRET =
  process.env.RENDERER_SHARED_SECRET ?? "";

const MAX_CONCURRENT_RENDERS = Math.max(
  1,
  Number(
    process.env.MAX_CONCURRENT_RENDERS ?? 2,
  ),
);

const RENDER_TIMEOUT_MS = Math.max(
  5000,
  Number(
    process.env.RENDER_TIMEOUT_MS ?? 45000,
  ),
);

if (!RENDERER_SHARED_SECRET) {
  throw new Error(
    "RENDERER_SHARED_SECRET must be configured",
  );
}

/* -------------------------------------------------------------------------- */
/* APP                                                                        */
/* -------------------------------------------------------------------------- */

const app = express();

console.log(
  `Starting Biz-BoT renderer ${RENDERER_VERSION}`,
);

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "40mb",
  }),
);

/* -------------------------------------------------------------------------- */
/* PLAYWRIGHT                                                                 */
/* -------------------------------------------------------------------------- */

const browserPromise = chromium.launch({
  headless: true,

  args: [
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-setuid-sandbox",
  ],
});

/* -------------------------------------------------------------------------- */
/* CONCURRENCY                                                                */
/* -------------------------------------------------------------------------- */

let activeRenders = 0;

const waiters = [];

function releaseSlot() {
  activeRenders = Math.max(
    0,
    activeRenders - 1,
  );

  const next = waiters.shift();

  if (next) {
    next();
  }
}

async function acquireSlot() {
  if (
    activeRenders <
    MAX_CONCURRENT_RENDERS
  ) {
    activeRenders += 1;
    return;
  }

  await new Promise((resolve) => {
    waiters.push(resolve);
  });

  activeRenders += 1;
}

/* -------------------------------------------------------------------------- */
/* NETWORK SAFETY                                                             */
/* -------------------------------------------------------------------------- */

function isPrivateIp(ip) {
  if (!ip) {
    return true;
  }

  if (net.isIPv4(ip)) {
    const parts = ip
      .split(".")
      .map(Number);

    const [a, b] = parts;

    // 10.0.0.0/8
    if (a === 10) {
      return true;
    }

    // 127.0.0.0/8
    if (a === 127) {
      return true;
    }

    // 0.0.0.0/8
    if (a === 0) {
      return true;
    }

    // 169.254.0.0/16
    if (
      a === 169 &&
      b === 254
    ) {
      return true;
    }

    // 172.16.0.0/12
    if (
      a === 172 &&
      b >= 16 &&
      b <= 31
    ) {
      return true;
    }

    // 192.168.0.0/16
    if (
      a === 192 &&
      b === 168
    ) {
      return true;
    }

    // Carrier-grade NAT
    // 100.64.0.0/10
    if (
      a === 100 &&
      b >= 64 &&
      b <= 127
    ) {
      return true;
    }

    return false;
  }

  const normalized =
    ip.toLowerCase();

  if (
    normalized === "::1" ||
    normalized === "::"
  ) {
    return true;
  }

  // IPv6 unique-local
  if (
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  ) {
    return true;
  }

  // IPv6 link-local
  if (
    normalized.startsWith("fe80:")
  ) {
    return true;
  }

  return false;
}

async function isSafePublicHttpUrl(
  rawUrl,
) {
  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (
    ![
      "http:",
      "https:",
    ].includes(parsed.protocol)
  ) {
    return false;
  }

  const hostname =
    parsed.hostname.toLowerCase();

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".local")
  ) {
    return false;
  }

  if (net.isIP(hostname)) {
    return !isPrivateIp(hostname);
  }

  try {
    const records =
      await dns.lookup(
        hostname,
        {
          all: true,
          verbatim: true,
        },
      );

    if (!records.length) {
      return false;
    }

    return records.every(
      (record) =>
        !isPrivateIp(
          record.address,
        ),
    );
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* AUTH                                                                       */
/* -------------------------------------------------------------------------- */

function authorized(req) {
  const auth =
    req.get("authorization") ?? "";

  return (
    auth ===
    `Bearer ${RENDERER_SHARED_SECRET}`
  );
}

/* -------------------------------------------------------------------------- */
/* HEALTH                                                                     */
/* -------------------------------------------------------------------------- */

app.get(
  "/health",
  (_req, res) => {
    res.json({
      ok: true,

      version:
        RENDERER_VERSION,

      activeRenders,

      maxConcurrentRenders:
        MAX_CONCURRENT_RENDERS,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* RENDER                                                                     */
/* -------------------------------------------------------------------------- */

app.post(
  "/render",
  async (req, res) => {
    if (!authorized(req)) {
      return res
        .status(401)
        .json({
          error: "Unauthorized",
        });
    }

    const {
      html,
      width,
      height,
    } = req.body ?? {};

    console.log(
      `[${RENDERER_VERSION}] Render request received: ${width}x${height}`,
    );

    /* ---------------------------------------------------------------------- */
    /* REQUEST VALIDATION                                                     */
    /* ---------------------------------------------------------------------- */

    if (
      typeof html !== "string" ||
      html.length < 20
    ) {
      return res
        .status(400)
        .json({
          error:
            "Missing or invalid html",
        });
    }

    if (
      !Number.isInteger(width) ||
      !Number.isInteger(height)
    ) {
      return res
        .status(400)
        .json({
          error:
            "width and height must be integers",
        });
    }

    if (
      width < 320 ||
      width > 3840 ||
      height < 320 ||
      height > 3840
    ) {
      return res
        .status(400)
        .json({
          error:
            "Unsupported render dimensions",
        });
    }

    await acquireSlot();

    let page = null;
    let context = null;

    try {
      const browser =
        await browserPromise;

      context =
        await browser.newContext({
          viewport: {
            width,
            height,
          },

          deviceScaleFactor: 1,

          javaScriptEnabled: true,
        });

      page =
        await context.newPage();

      page.setDefaultTimeout(
        RENDER_TIMEOUT_MS,
      );

      page.setDefaultNavigationTimeout(
        RENDER_TIMEOUT_MS,
      );

      /* -------------------------------------------------------------------- */
      /* NETWORK FILTER                                                       */
      /* -------------------------------------------------------------------- */

      await page.route(
        "**/*",
        async (route) => {
          const requestUrl =
            route
              .request()
              .url();

          if (
            requestUrl.startsWith(
              "data:",
            ) ||
            requestUrl.startsWith(
              "blob:",
            ) ||
            requestUrl ===
              "about:blank"
          ) {
            return route.continue();
          }

          const safe =
            await isSafePublicHttpUrl(
              requestUrl,
            );

          if (safe) {
            return route.continue();
          }

          console.warn(
            `[${RENDERER_VERSION}] Blocked external resource:`,
            requestUrl,
          );

          return route.abort(
            "blockedbyclient",
          );
        },
      );

      /* -------------------------------------------------------------------- */
      /* LOAD FLYER                                                           */
      /* -------------------------------------------------------------------- */

      await page.setContent(
        html,
        {
          waitUntil: "load",

          timeout:
            RENDER_TIMEOUT_MS,
        },
      );

      /* -------------------------------------------------------------------- */
      /* WAIT FOR FONTS + IMAGES                                              */
      /* -------------------------------------------------------------------- */

      await page.evaluate(
        async () => {
          if (
            document.fonts?.ready
          ) {
            try {
              await document.fonts.ready;
            } catch {
              // Continue if a browser/font
              // implementation rejects ready.
            }
          }

          const images =
            Array.from(
              document.images,
            );

          await Promise.all(
            images.map(
              async (img) => {
                if (!img.complete) {
                  await new Promise(
                    (resolve) => {
                      const done =
                        () =>
                          resolve(
                            undefined,
                          );

                      img.addEventListener(
                        "load",
                        done,
                        {
                          once: true,
                        },
                      );

                      img.addEventListener(
                        "error",
                        done,
                        {
                          once: true,
                        },
                      );
                    },
                  );
                }

                if (
                  typeof img.decode ===
                  "function"
                ) {
                  try {
                    await img.decode();
                  } catch {
                    // Continue.
                  }
                }
              },
            ),
          );

          /*
           * Give Chromium two complete
           * layout frames after fonts/images
           * become available.
           */
          await new Promise(
            (resolve) =>
              requestAnimationFrame(
                () =>
                  requestAnimationFrame(
                    resolve,
                  ),
              ),
          );

          /*
           * Additional tiny settle period for
           * font metrics, flex/grid and image
           * calculations.
           */
          await new Promise(
            (resolve) =>
              setTimeout(
                resolve,
                80,
              ),
          );
        },
      );

      /* -------------------------------------------------------------------- */
      /* FIND FLYER ROOT                                                      */
      /* -------------------------------------------------------------------- */

      const root =
        page.locator(
          ".flyer-root",
        );

      const rootCount =
        await root.count();

      if (rootCount !== 1) {
        throw new Error(
          `Expected exactly one .flyer-root element, found ${rootCount}`,
        );
      }

      /* -------------------------------------------------------------------- */
      /* EMERGENCY SERVER-SIDE TEXT FIT                                       */
      /* -------------------------------------------------------------------- */

      const fitResult =
        await page.evaluate(() => {
          /*
           * These selectors match the
           * deterministic Content Studio
           * template zones.
           */
          const rules = [
            {
              selector:
                ".flyer-badge",
              minPx: 11,
            },

            {
              selector:
                ".brand-wordmark",
              minPx: 13,
            },

            {
              selector:
                ".flyer-eyebrow",
              minPx: 11,
            },

            {
              selector:
                ".flyer-headline",
              minPx: 26,
            },

            {
              selector:
                ".flyer-subheadline",
              minPx: 14,
            },

            {
              selector:
                ".flyer-cta",
              minPx: 13,
            },

            {
              selector:
                ".footer-label",
              minPx: 10,
            },

            {
              selector:
                ".footer-phone",
              minPx: 13,
            },

            {
              selector:
                ".footer-message",
              minPx: 10,
            },
          ];

          /*
           * A couple of Chromium font/rendering
           * situations may produce a 1-2px
           * scrollHeight difference even when
           * nothing is visibly clipped.
           */
          const FIT_TOLERANCE_PX = 2;

          function getOverflow(el) {
            return {
              x: Math.max(
                0,
                el.scrollWidth -
                  el.clientWidth,
              ),

              y: Math.max(
                0,
                el.scrollHeight -
                  el.clientHeight,
              ),
            };
          }

          const repaired = [];

          for (
            const rule of rules
          ) {
            const elements =
              Array.from(
                document.querySelectorAll(
                  rule.selector,
                ),
              );

            for (
              let index = 0;
              index <
              elements.length;
              index += 1
            ) {
              const el =
                elements[index];

              if (
                !(
                  el instanceof
                  HTMLElement
                )
              ) {
                continue;
              }

              /*
               * Ignore elements that are not
               * actually visible.
               */
              const style =
                getComputedStyle(el);

              if (
                style.display ===
                  "none" ||
                style.visibility ===
                  "hidden"
              ) {
                continue;
              }

              let overflow =
                getOverflow(el);

              if (
                overflow.x <=
                  FIT_TOLERANCE_PX &&
                overflow.y <=
                  FIT_TOLERANCE_PX
              ) {
                continue;
              }

              let fontSize =
                Number.parseFloat(
                  style.fontSize ||
                    "0",
                );

              if (
                !Number.isFinite(
                  fontSize,
                ) ||
                fontSize <= 0
              ) {
                continue;
              }

              const originalFontSize =
                fontSize;

              let iterations = 0;

              /*
               * Shrink in 1px increments.
               *
               * This is intentionally
               * conservative because Content
               * Studio has already sized the
               * typography once.
               */
              while (
                (
                  overflow.x >
                    FIT_TOLERANCE_PX ||
                  overflow.y >
                    FIT_TOLERANCE_PX
                ) &&
                fontSize >
                  rule.minPx &&
                iterations < 100
              ) {
                fontSize =
                  Math.max(
                    rule.minPx,
                    fontSize - 1,
                  );

                el.style.setProperty(
                  "font-size",
                  `${fontSize}px`,
                  "important",
                );

                /*
                 * If the generated design uses
                 * a fixed line-height measured
                 * in pixels, shrinking only the
                 * font can still leave the line
                 * box too tall.
                 *
                 * If line-height is a pixel
                 * value, reduce it proportionally.
                 */
                const updatedStyle =
                  getComputedStyle(
                    el,
                  );

                const lineHeight =
                  Number.parseFloat(
                    updatedStyle.lineHeight,
                  );

                if (
                  Number.isFinite(
                    lineHeight,
                  ) &&
                  lineHeight > 0
                ) {
                  const safeLineHeight =
                    Math.max(
                      fontSize *
                        1.02,
                      Math.min(
                        lineHeight,
                        fontSize *
                          1.3,
                      ),
                    );

                  el.style.setProperty(
                    "line-height",
                    `${safeLineHeight}px`,
                    "important",
                  );
                }

                /*
                 * Reading layout values here
                 * forces Chromium to recalculate
                 * this element before deciding
                 * whether another reduction is
                 * necessary.
                 */
                overflow =
                  getOverflow(el);

                iterations += 1;
              }

              if (
                fontSize !==
                  originalFontSize ||
                overflow.x >
                  FIT_TOLERANCE_PX ||
                overflow.y >
                  FIT_TOLERANCE_PX
              ) {
                repaired.push({
                  selector:
                    rule.selector,

                  index,

                  from:
                    originalFontSize,

                  to:
                    fontSize,

                  remainingOverflowX:
                    overflow.x,

                  remainingOverflowY:
                    overflow.y,

                  clientWidth:
                    el.clientWidth,

                  scrollWidth:
                    el.scrollWidth,

                  clientHeight:
                    el.clientHeight,

                  scrollHeight:
                    el.scrollHeight,
                });
              }
            }
          }

          return repaired;
        });

      if (
        fitResult.length > 0
      ) {
        console.log(
          `[${RENDERER_VERSION}] Renderer emergency text-fit applied`,
          JSON.stringify(
            fitResult,
          ),
        );

        /*
         * Re-run the browser layout after
         * modifications.
         */
        await page.evaluate(
          async () => {
            await new Promise(
              (resolve) =>
                requestAnimationFrame(
                  () =>
                    requestAnimationFrame(
                      resolve,
                    ),
                ),
            );

            await new Promise(
              (resolve) =>
                setTimeout(
                  resolve,
                  50,
                ),
            );
          },
        );
      }

      /* -------------------------------------------------------------------- */
      /* FINAL OVERFLOW VALIDATION                                             */
      /* -------------------------------------------------------------------- */

      const overflow =
        await page.evaluate(() => {
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

          /*
           * Up to four pixels are allowed
           * during final validation.
           *
           * This accommodates harmless
           * Chromium font-metric differences.
           *
           * Actual clipping larger than this
           * still prevents export.
           */
          const FINAL_TOLERANCE_PX =
            4;

          const problems = [];

          for (
            const selector of selectors
          ) {
            const elements =
              Array.from(
                document.querySelectorAll(
                  selector,
                ),
              );

            for (
              let index = 0;
              index <
              elements.length;
              index += 1
            ) {
              const el =
                elements[index];

              if (
                !(
                  el instanceof
                  HTMLElement
                )
              ) {
                continue;
              }

              const style =
                getComputedStyle(el);

              if (
                style.display ===
                  "none" ||
                style.visibility ===
                  "hidden"
              ) {
                continue;
              }

              const overflowX =
                Math.max(
                  0,
                  el.scrollWidth -
                    el.clientWidth,
                );

              const overflowY =
                Math.max(
                  0,
                  el.scrollHeight -
                    el.clientHeight,
                );

              if (
                overflowX >
                  FINAL_TOLERANCE_PX ||
                overflowY >
                  FINAL_TOLERANCE_PX
              ) {
                problems.push({
                  selector,

                  index,

                  scrollWidth:
                    el.scrollWidth,

                  clientWidth:
                    el.clientWidth,

                  scrollHeight:
                    el.scrollHeight,

                  clientHeight:
                    el.clientHeight,

                  overflowX,

                  overflowY,

                  fontSize:
                    getComputedStyle(
                      el,
                    ).fontSize,

                  lineHeight:
                    getComputedStyle(
                      el,
                    ).lineHeight,
                });
              }
            }
          }

          return problems;
        });

      if (
        overflow.length > 0
      ) {
        console.error(
          `[${RENDERER_VERSION}] Render rejected because text still overflows after emergency fit`,
          JSON.stringify(
            overflow,
          ),
        );

        return res
          .status(422)
          .json({
            error:
              "Flyer layout overflow detected",

            rendererVersion:
              RENDERER_VERSION,

            overflow,
          });
      }

      /* -------------------------------------------------------------------- */
      /* FINAL LAYOUT INFORMATION                                              */
      /* -------------------------------------------------------------------- */

      const bounds =
        await root.boundingBox();

      if (!bounds) {
        throw new Error(
          "Unable to determine flyer dimensions",
        );
      }

      console.log(
        `[${RENDERER_VERSION}] Rendering PNG`,
        {
          requestedWidth:
            width,

          requestedHeight:
            height,

          renderedWidth:
            bounds.width,

          renderedHeight:
            bounds.height,
        },
      );

      /* -------------------------------------------------------------------- */
      /* SCREENSHOT                                                           */
      /* -------------------------------------------------------------------- */

      const png =
        await root.screenshot({
          type: "png",

          animations:
            "disabled",

          caret: "hide",

          scale: "css",

          timeout:
            RENDER_TIMEOUT_MS,
        });

      console.log(
        `[${RENDERER_VERSION}] PNG successfully rendered (${png.length} bytes)`,
      );

      /* -------------------------------------------------------------------- */
      /* RESPONSE                                                             */
      /* -------------------------------------------------------------------- */

      res.setHeader(
        "Content-Type",
        "image/png",
      );

      res.setHeader(
        "Content-Length",
        String(
          png.length,
        ),
      );

      res.setHeader(
        "Cache-Control",
        "no-store",
      );

      res.setHeader(
        "X-BizBot-Renderer-Version",
        RENDERER_VERSION,
      );

      return res
        .status(200)
        .send(png);
    } catch (error) {
      console.error(
        `[${RENDERER_VERSION}] Render failed`,
        error,
      );

      if (!res.headersSent) {
        return res
          .status(500)
          .json({
            error:
              error instanceof Error
                ? error.message
                : "Render failed",

            rendererVersion:
              RENDERER_VERSION,
          });
      }
    } finally {
      try {
        if (context) {
          await context.close();
        }
      } catch (error) {
        console.warn(
          `[${RENDERER_VERSION}] Failed to close browser context`,
          error,
        );
      }

      releaseSlot();
    }
  },
);

/* -------------------------------------------------------------------------- */
/* SERVER                                                                     */
/* -------------------------------------------------------------------------- */

const server =
  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Biz-BoT flyer renderer ${RENDERER_VERSION} listening on :${PORT}`,
      );
    },
  );

/* -------------------------------------------------------------------------- */
/* GRACEFUL SHUTDOWN                                                          */
/* -------------------------------------------------------------------------- */

async function shutdown(
  signal,
) {
  console.log(
    `[${RENDERER_VERSION}] Received ${signal}; shutting down`,
  );

  server.close(
    async () => {
      try {
        const browser =
          await browserPromise;

        await browser.close();
      } catch (error) {
        console.error(
          `[${RENDERER_VERSION}] Error closing browser`,
          error,
        );
      }

      process.exit(0);
    },
  );
}

process.on(
  "SIGTERM",
  () => {
    shutdown("SIGTERM");
  },
);

process.on(
  "SIGINT",
  () => {
    shutdown("SIGINT");
  },
);
