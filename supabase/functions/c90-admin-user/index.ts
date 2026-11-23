import { createClient } from "https://esm.sh/@supabase/supabase-js@2.57.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return json({ error: "ابتدا وارد حساب مدیر شو" }, 401);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return json({ error: "تنظیمات محرمانه سرور کامل نیست" }, 500);
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "نشست معتبر نیست؛ دوباره وارد شو" }, 401);

    const actorId = authData.user.id;
    const { data: actor, error: actorError } = await adminClient
      .from("profiles").select("role").eq("user_id", actorId).maybeSingle();
    if (actorError) return json({ error: "بررسی سطح دسترسی مدیر انجام نشد" }, 500);
    if (actor?.role !== "admin") return json({ error: "فقط مدیر مجاز به این عملیات است" }, 403);

    const body = await req.json().catch(() => null);
    const action = body?.action;
    const targetId = typeof body?.user_id === "string" ? body.user_id : "";
    if (!targetId || targetId === actorId) return json({ error: "حساب انتخاب‌شده معتبر نیست" }, 400);

    const { data: target, error: targetError } = await adminClient
      .from("profiles").select("role, username").eq("user_id", targetId).maybeSingle();
    if (targetError) return json({ error: "بررسی حساب انتخاب‌شده ناموفق بود" }, 500);
    if (!target) return json({ error: "حساب کاربر پیدا نشد" }, 404);
    if (target.role === "admin") return json({ error: "تغییر رمز مدیران از این بخش مجاز نیست" }, 403);

    if (action === "reset_password") {
      const password = typeof body?.password === "string" ? body.password : "";
      if (password.length < 8 || password.length > 72) {
        return json({ error: "رمز باید بین ۸ تا ۷۲ نویسه باشد" }, 400);
      }
      const { error } = await adminClient.auth.admin.updateUserById(targetId, { password });
      if (error) return json({ error: "تغییر رمز انجام نشد؛ تنظیمات Auth را بررسی کن" }, 400);
      return json({ success: true, message: "رمز عبور کاربر تغییر کرد" });
    }

    return json({ error: "عملیات ناشناخته است" }, 400);
  } catch (_error) {
    return json({ error: "خطای داخلی سرور؛ عملیات انجام نشد" }, 500);
  }
});
