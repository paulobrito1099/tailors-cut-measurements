/**
 * The Tailor's Cut — Measurements App Proxy backend
 * ---------------------------------------------------
 * Handles two routes, both called by Shopify's App Proxy (so requests
 * arrive already signed by Shopify — we just verify that signature):
 *
 *   GET  /apps/measurements        -> returns the logged-in customer's saved measurements
 *   POST /apps/measurements/save   -> saves/updates the logged-in customer's measurements
 *
 * Requires a Custom App (or Partner app) with:
 *   - Admin API scope: write_customers, read_customers
 *   - App Proxy configured: Subpath prefix "apps", Subpath "measurements",
 *     pointing at this server's public URL.
 *
 * Env vars needed (see .env.example):
 *   SHOPIFY_APP_SECRET   - App Proxy shared secret (from your app's API credentials)
 *   SHOPIFY_STORE_DOMAIN - e.g. thetailorscut.myshopify.com
 *   SHOPIFY_ADMIN_TOKEN  - Admin API access token for the custom app
 */

const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());

const {
  SHOPIFY_APP_SECRET,
  SHOPIFY_STORE_DOMAIN,
  SHOPIFY_ADMIN_TOKEN,
  PORT = 3000,
} = process.env;

// The measurement fields. Keep this list in sync with the metafield
// definitions you created in Shopify admin (namespace: "measurements").
const MEASUREMENT_KEYS = [
  "height",
  "weight",
  "full_chest",
  "stomach",
  "bicep",
  "shoulder_width",
  "sleeve_length",
  "jacket_length",
  "leg_outseam",
  "leg_inseam",
  "thigh",
  "waist",
  "hips",
  "collar",
  "cuff",
  "shirt_length",
  "embroidered_initials",
  "length",
  "width",
];

const ADMIN_API_URL = `https://${SHOPIFY_STORE_DOMAIN}/admin/api/2026-04/graphql.json`;

/**
 * Verifies that a request genuinely came through Shopify's App Proxy.
 * Shopify signs every proxy request with your app's shared secret.
 * https://shopify.dev/docs/apps/build/online-store/display-dynamic-data#verify-the-request
 */
function verifyProxySignature(query) {
  const { signature, ...rest } = query;
  if (!signature) return false;

  const sorted = Object.keys(rest)
    .sort()
    .map((key) => {
      const value = Array.isArray(rest[key]) ? rest[key].join(",") : rest[key];
      return `${key}=${value}`;
    })
    .join("");

  const computed = crypto
    .createHmac("sha256", SHOPIFY_APP_SECRET)
    .update(sorted)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
}

async function adminGraphQL(query, variables) {
  const res = await fetch(ADMIN_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) {
    throw new Error(JSON.stringify(json.errors));
  }
  return json.data;
}

// ---- GET / -----------------------------------------------------------------
// Shopify's App Proxy forwards yourstore.com/apps/measurements -> this Proxy
// URL's root. Do not change this to "/apps/measurements" - that portion of
// the path is stripped off by Shopify before the request reaches here.
//
// Returns the logged-in customer's currently saved measurements (or an
// empty object if they haven't saved any yet, or aren't logged in).
app.get("/", async (req, res) => {
  if (!verifyProxySignature(req.query)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const customerId = req.query.logged_in_customer_id;
  if (!customerId) {
    // Not logged in — nothing to prefill.
    return res.json({ measurements: {} });
  }

  const gid = `gid://shopify/Customer/${customerId}`;

  const query = `
    query GetMeasurements($id: ID!) {
      customer(id: $id) {
        metafields(namespace: "measurements", first: 20) {
          edges { node { key value } }
        }
      }
    }
  `;

  try {
    const data = await adminGraphQL(query, { id: gid });
    const measurements = {};
    (data.customer?.metafields?.edges || []).forEach(({ node }) => {
      measurements[node.key] = node.value;
    });
    res.json({ measurements });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch measurements" });
  }
});

// ---- POST /save --------------------------------------------------------
// Forwarded from yourstore.com/apps/measurements/save (see note above).
// Saves/updates the logged-in customer's measurements.
// Body: { measurements: { full_chest: "104.5", waist: "88", ... } }
app.post("/save", async (req, res) => {
  if (!verifyProxySignature(req.query)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const customerId = req.query.logged_in_customer_id;
  if (!customerId) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const gid = `gid://shopify/Customer/${customerId}`;
  const incoming = req.body.measurements || {};

  // Only accept known keys, and only ones that were actually sent with a value.
  const metafields = MEASUREMENT_KEYS.filter(
    (key) => incoming[key] !== undefined && incoming[key] !== ""
  ).map((key) => ({
    ownerId: gid,
    namespace: "measurements",
    key,
    type: key === "embroidered_initials" ? "single_line_text_field" : "number_decimal",
    value: String(incoming[key]),
  }));

  if (metafields.length === 0) {
    return res.status(400).json({ error: "No measurement values provided" });
  }

  const mutation = `
    mutation SetMeasurements($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields { key value }
        userErrors { field message }
      }
    }
  `;

  try {
    const data = await adminGraphQL(mutation, { metafields });
    if (data.metafieldsSet.userErrors.length > 0) {
      return res.status(400).json({ error: data.metafieldsSet.userErrors });
    }
    res.json({ success: true, saved: data.metafieldsSet.metafields });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save measurements" });
  }
});

app.listen(PORT, () => {
  console.log(`Measurements app proxy backend running on port ${PORT}`);
});
