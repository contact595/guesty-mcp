const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { SSEServerTransport } = require("@modelcontextprotocol/sdk/server/sse.js");
const { z } = require("zod");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const BASE_URL = process.env.BASE_URL || "https://guesty-mcp.onrender.com";

// ─── In-memory stores (fine for single-user MCP) ────────────────────────────
const clients = {};       // Dynamic Client Registration store
const authCodes = {};     // Authorization codes
const accessTokens = {};  // Issued tokens

// ─── Guesty Token Cache ──────────────────────────────────────────────────────
let cachedToken = null;
let tokenExpiresAt = null;

async function getGuestyToken() {
  if (cachedToken && tokenExpiresAt && Date.now() < tokenExpiresAt) return cachedToken;
  const res = await axios.post(
    "https://open-api.guesty.com/oauth2/token",
    new URLSearchParams({
      grant_type: "client_credentials",
      scope: "open-api",
      client_id: process.env.GUESTY_CLIENT_ID,
      client_secret: process.env.GUESTY_CLIENT_SECRET,
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" } }
  );
  cachedToken = res.data.access_token;
  tokenExpiresAt = Date.now() + 23 * 60 * 60 * 1000;
  return cachedToken;
}

async function guestyRequest(method, path, params = {}, body = null) {
  const token = await getGuestyToken();
  const config = {
    method,
    url: `https://open-api.guesty.com/v1${path}`,
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  };
  if (method === "GET" && Object.keys(params).length) config.params = params;
  if (body) { config.data = body; config.headers["Content-Type"] = "application/json"; }
  const res = await axios(config);
  return res.data;
}

// ═══════════════════════════════════════════════════════════════════════════
// OAuth 2.1 Endpoints (required by Claude.ai)
// ═══════════════════════════════════════════════════════════════════════════

// 1. Protected Resource Metadata (RFC 9728) - Claude checks this first
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: BASE_URL,
    authorization_servers: [BASE_URL],
    bearer_methods_supported: ["header"],
  });
});

// 2. Authorization Server Metadata (RFC 8414) - Claude discovers endpoints here
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  });
});

// 3. Dynamic Client Registration (RFC 7591) - Claude registers itself
app.post("/register", (req, res) => {
  const clientId = `claude_${crypto.randomBytes(8).toString("hex")}`;
  const client = {
    client_id: clientId,
    client_secret: null,
    redirect_uris: req.body.redirect_uris || [],
    client_name: req.body.client_name || "Claude",
    grant_types: ["authorization_code"],
    response_types: ["code"],
  };
  clients[clientId] = client;
  console.log(`[OAuth] Registered client: ${clientId}`);
  res.status(201).json({
    client_id: clientId,
    client_secret_expires_at: 0,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    response_types: client.response_types,
    client_name: client.client_name,
  });
});

// 4. Authorization Endpoint - Shows auto-approve consent page
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;

  if (!client_id) return res.status(400).send("Missing client_id");

  // Generate auth code
  const code = crypto.randomBytes(16).toString("hex");
  authCodes[code] = {
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    created_at: Date.now(),
  };

  // Auto-approve consent page (single-user server - you are the only user)
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guesty MCP – Connect to Claude</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 4px 20px rgba(0,0,0,0.08);
      text-align: center;
    }
    .logo { font-size: 40px; margin-bottom: 16px; }
    h1 { font-size: 22px; color: #111; margin-bottom: 8px; }
    p { color: #666; font-size: 14px; margin-bottom: 24px; line-height: 1.5; }
    .scopes {
      background: #f9f9f9;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      text-align: left;
    }
    .scope-item {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      color: #444;
      padding: 4px 0;
    }
    .scope-item::before { content: "✓"; color: #22c55e; font-weight: bold; }
    .btn {
      display: block;
      width: 100%;
      padding: 14px;
      background: #2563eb;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s;
    }
    .btn:hover { background: #1d4ed8; }
    .powered { margin-top: 20px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🏠</div>
    <h1>Connect Guesty to Claude</h1>
    <p>Claude is requesting access to your Guesty account for Ventur Group. Click below to authorize.</p>
    <div class="scopes">
      <div class="scope-item">View listings and properties</div>
      <div class="scope-item">Read and manage reservations</div>
      <div class="scope-item">Access guest information</div>
      <div class="scope-item">Send messages via inbox</div>
      <div class="scope-item">View availability and financials</div>
    </div>
    <a class="btn" href="/authorize/approve?code=${code}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${encodeURIComponent(state || "")}">
      Authorize Access
    </a>
    <div class="powered">Guesty MCP • Ventur Group</div>
  </div>
</body>
</html>`);
});

// 5. Approval redirect - sends code back to Claude
app.get("/authorize/approve", (req, res) => {
  const { code, redirect_uri, state } = req.query;
  if (!code || !authCodes[code]) return res.status(400).send("Invalid or expired authorization code");

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  console.log(`[OAuth] Approved, redirecting to: ${redirectUrl.toString()}`);
  res.redirect(redirectUrl.toString());
});

// 6. Token Endpoint - exchanges code for access token
app.post("/token", (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const authCode = authCodes[code];
  if (!authCode) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired code" });
  }

  // Verify PKCE if code_challenge was provided
  if (authCode.code_challenge && code_verifier) {
    const verifierHash = crypto
      .createHash("sha256")
      .update(code_verifier)
      .digest("base64url");
    if (verifierHash !== authCode.code_challenge) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }
  }

  // Issue access token
  const accessToken = crypto.randomBytes(32).toString("hex");
  accessTokens[accessToken] = {
    client_id: authCode.client_id,
    created_at: Date.now(),
    expires_at: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year
  };

  delete authCodes[code]; // One-time use

  console.log(`[OAuth] Issued access token for client: ${authCode.client_id}`);
  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 31536000,
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Token validation middleware for MCP endpoints
// ═══════════════════════════════════════════════════════════════════════════
function validateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401)
      .set("WWW-Authenticate", `Bearer realm="${BASE_URL}", resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`)
      .json({ error: "unauthorized" });
  }
  const token = auth.slice(7);
  const tokenData = accessTokens[token];
  if (!tokenData || Date.now() > tokenData.expires_at) {
    return res.status(401)
      .set("WWW-Authenticate", `Bearer realm="${BASE_URL}", error="invalid_token"`)
      .json({ error: "invalid_token" });
  }
  next();
}

// ═══════════════════════════════════════════════════════════════════════════
// MCP Tools
// ═══════════════════════════════════════════════════════════════════════════
function createMcpServer() {
  const server = new McpServer({ name: "guesty-mcp", version: "1.0.0" });

  server.tool("list_listings", "Get all Guesty property listings",
    { limit: z.number().optional().default(25), skip: z.number().optional().default(0) },
    async ({ limit, skip }) => {
      const data = await guestyRequest("GET", "/listings", { limit, skip, fields: "_id nickname title address type picture" });
      const listings = (data.results || data).map((l) => ({
        id: l._id, nickname: l.nickname, title: l.title,
        address: l.address?.full, type: l.type,
      }));
      return { content: [{ type: "text", text: JSON.stringify(listings, null, 2) }] };
    }
  );

  server.tool("get_listing", "Get full details for a single listing",
    { listing_id: z.string() },
    async ({ listing_id }) => {
      const data = await guestyRequest("GET", `/listings/${listing_id}`);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool("list_reservations", "Get reservations with optional filters",
    {
      listing_id: z.string().optional(),
      status: z.enum(["inquiry","reserved","confirmed","canceled","declined","expired","closed","checked_in","checked_out"]).optional(),
      check_in_from: z.string().optional(),
      check_in_to: z.string().optional(),
      limit: z.number().optional().default(20),
      skip: z.number().optional().default(0),
    },
    async ({ listing_id, status, check_in_from, check_in_to, limit, skip }) => {
      const params = { limit, skip };
      if (listing_id) params.listingId = listing_id;
      if (status) params.status = status;
      if (check_in_from) params.checkInDateFrom = check_in_from;
      if (check_in_to) params.checkInDateTo = check_in_to;
      const data = await guestyRequest("GET", "/reservations", params);
      const reservations = (data.results || data).map((r) => ({
        id: r._id, confirmationCode: r.confirmationCode, status: r.status,
        checkIn: r.checkIn, checkOut: r.checkOut, listingId: r.listingId,
        guestName: r.guest?.fullName, totalPaid: r.money?.totalPaid,
        currency: r.money?.currency, channel: r.source, nightsCount: r.nightsCount,
      }));
      return { content: [{ type: "text", text: JSON.stringify(reservations, null, 2) }] };
    }
  );

  server.tool("get_reservation", "Get full details for a single reservation",
    { reservation_id: z.string() },
    async ({ reservation_id }) => {
      const data = await guestyRequest("GET", `/reservations/${reservation_id}`);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool("update_reservation", "Update notes on a reservation",
    { reservation_id: z.string(), notes: z.string().optional() },
    async ({ reservation_id, notes }) => {
      const body = {};
      if (notes !== undefined) body.notes = notes;
      const data = await guestyRequest("PUT", `/reservations/${reservation_id}`, {}, body);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, id: data._id }) }] };
    }
  );

  server.tool("list_guests", "Search guests by name or email",
    { search: z.string().optional(), limit: z.number().optional().default(20), skip: z.number().optional().default(0) },
    async ({ search, limit, skip }) => {
      const params = { limit, skip };
      if (search) params.q = search;
      const data = await guestyRequest("GET", "/guests-crud", params);
      const guests = (data.results || data).map((g) => ({
        id: g._id, fullName: g.fullName, email: g.email, phone: g.phone,
      }));
      return { content: [{ type: "text", text: JSON.stringify(guests, null, 2) }] };
    }
  );

  server.tool("get_guest", "Get full profile for a guest",
    { guest_id: z.string() },
    async ({ guest_id }) => {
      const data = await guestyRequest("GET", `/guests-crud/${guest_id}`);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool("send_guest_message", "Send a message to a guest",
    { reservation_id: z.string(), message: z.string() },
    async ({ reservation_id, message }) => {
      const data = await guestyRequest("POST", `/conversations/${reservation_id}/messages`, {}, { body: message, type: "host" });
      return { content: [{ type: "text", text: JSON.stringify({ success: true, messageId: data._id }) }] };
    }
  );

  server.tool("get_conversation", "Get the message thread for a reservation",
    { reservation_id: z.string() },
    async ({ reservation_id }) => {
      const data = await guestyRequest("GET", `/conversations/${reservation_id}`);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool("get_availability_calendar", "Get availability calendar for a listing",
    { listing_id: z.string(), start_date: z.string(), end_date: z.string() },
    async ({ listing_id, start_date, end_date }) => {
      const data = await guestyRequest("GET", `/availability-pricing/api/v3/listings/${listing_id}/calendar`, { startDate: start_date, endDate: end_date });
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool("get_reservation_financials", "Get financial breakdown for a reservation",
    { reservation_id: z.string() },
    async ({ reservation_id }) => {
      const data = await guestyRequest("GET", `/reservations/${reservation_id}`);
      const money = data.money || {};
      return { content: [{ type: "text", text: JSON.stringify({
        reservationId: reservation_id, confirmationCode: data.confirmationCode,
        currency: money.currency, totalPaid: money.totalPaid, hostPayout: money.hostPayout,
        cleaningFee: money.cleaningFee, netIncome: money.netIncome,
        accommodationFare: money.fareAccommodation,
      }, null, 2) }] };
    }
  );

  return server;
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE MCP Endpoint (protected)
// ═══════════════════════════════════════════════════════════════════════════
const transports = {};

app.get("/sse", validateToken, async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  transports[transport.sessionId] = transport;
  res.on("close", () => delete transports[transport.sessionId]);
  const server = createMcpServer();
  await server.connect(transport);
});

app.post("/messages", validateToken, async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (!transport) return res.status(404).send("Session not found");
  await transport.handlePostMessage(req, res);
});

// ─── Health Check ─────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "guesty-mcp", version: "2.0.0", timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Guesty MCP server v2 running on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`OAuth metadata: ${BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`SSE endpoint: ${BASE_URL}/sse`);
});
