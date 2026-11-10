const express = require("express");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");

const app = express();
app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));

const ALLOWED_HOSTS = new Set(["speedy-links.com", "www.speedy-links.com"]);
const BLOCKED_V4 = [
  /^0\./, /^10\./, /^127\./, /^169\.254\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^192\.0\.0\./, /^198\.(18|19)\./, /^22[4-9]\./, /^23\d\./, /^24\d\./
];

function isPublicIp(ip) {
  if (net.isIPv4(ip)) return !BLOCKED_V4.some((re) => re.test(ip));
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return !(v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80:") || v.startsWith("::ffff:127."));
  }
  return false;
}

async function validateHost(hostname) {
  if (!ALLOWED_HOSTS.has(hostname.toLowerCase())) throw new Error("Only speedy-links.com URLs are supported.");
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((r) => !isPublicIp(r.address))) throw new Error("The host did not pass the public-address safety check.");
}

function findLinks(html) {
  const found = new Set();
  const patterns = [
    /https?:\\?\/\\?\/[a-z0-9.-]+(?:\\?\/[^\s"'<>]*)?/gi,
    /https?:\/\/[a-z0-9.-]+(?:\/[^\s"'<>]*)?/gi,
    /https?:%2f%2f[^\s"'<>]*/gi
  ];
  for (const re of patterns) {
    for (const m of html.matchAll(re)) {
      const cleaned = m[0].replace(/\\\//g, "/").replace(/&amp;/g, "&").replace(/[),.;]+$/, "");
      try {
        const u = new URL(cleaned);
        if (["http:", "https:"].includes(u.protocol)) found.add(u.href);
      } catch {}
    }
  }
  return [...found].slice(0, 80);
}

app.post("/api/inspect", async (req, res) => {
  try {
    const raw = String(req.body?.url || "").trim();
    const target = new URL(raw);
    if (target.protocol !== "https:") return res.status(400).json({ error: "Please enter an HTTPS SpeedyLinks URL." });
    await validateHost(target.hostname);

    const response = await fetch(target.href, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": "LinkUnlockInspector/1.0 (+public redirect inspection)", "accept": "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(10000)
    });

    const location = response.headers.get("location");
    if (location) {
      let next;
      try { next = new URL(location, target).href; } catch {}
      let sameHost = false;
      try { sameHost = new URL(next).hostname.toLowerCase() === target.hostname.toLowerCase(); } catch {}
      return res.json({
        status: response.status,
        redirect: next || location,
        followed: false,
        note: sameHost
          ? "A redirect was found. Open the destination in your browser if you trust it."
          : "An external redirect was found but was not followed. The inspector does not bypass task locks."
      });
    }

    const type = response.headers.get("content-type") || "";
    if (!type.includes("text/html")) return res.json({ status: response.status, note: "The response is not an HTML page.", links: [] });
    const html = (await response.text()).slice(0, 1_500_000);
    const links = findLinks(html);
    const mega = links.filter((x) => /(^|\.)mega\.nz$/i.test(new URL(x).hostname));
    res.json({
      status: response.status,
      pageTitle: (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "").replace(/<[^>]+>/g, "").trim().slice(0, 200),
      links,
      megaLinks: mega,
      note: mega.length ? "A publicly exposed MEGA link was found." : "No public MEGA link was found in the returned HTML. Server-side or task-gated destinations cannot be revealed by this inspector."
    });
  } catch (error) {
    res.status(400).json({ error: error.message || "Inspection failed." });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("LinkUnlock Inspector listening on " + port));