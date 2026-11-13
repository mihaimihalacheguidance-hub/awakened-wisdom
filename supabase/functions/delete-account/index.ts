// Deletes the calling user's account. Rows in user_state, user_days, circle_members
// and join_attempts cascade; feedback keeps the text with user_id set to null.
// The service-role key is provided by the Edge runtime and never leaves the server.
import { createClient } from "npm:@supabase/supabase-js@2.49.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "not signed in" }, 401);

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data.user) return json({ error: "not signed in" }, 401);
  const uid = data.user.id;

  // circles this user leaves empty go too
  const { data: mine, error: mineErr } = await admin.from("circle_members").select("circle_id").eq("user_id", uid);
  if (mineErr) return json({ error: "could not delete account" }, 500);

  const { error: delErr } = await admin.auth.admin.deleteUser(uid);
  if (delErr) return json({ error: "could not delete account" }, 500);

  for (const { circle_id } of mine ?? []) {
    const { count, error: cErr } = await admin
      .from("circle_members").select("*", { count: "exact", head: true }).eq("circle_id", circle_id);
    // only a circle known to be empty goes; on any error it stays
    if (!cErr && count === 0) await admin.from("circles").delete().eq("id", circle_id);
  }
  return json({ deleted: true });
});
