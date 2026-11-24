import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token) return json({ error: "نشست ورود معتبر نیست." }, 401);
    const url = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!serviceKey) return json({ error: "تنظیمات امن سرور ناقص است." }, 500);

    const userClient = createClient(url, anonKey, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "نشست ورود معتبر نیست." }, 401);

    const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: actor, error: actorError } = await admin.from("profiles").select("role")
      .eq("user_id", authData.user.id).maybeSingle();
    if (actorError || actor?.role !== "admin") return json({ error: "فقط مدیر مجاز به تغییر نام کاربری است." }, 403);

    const body = await req.json().catch(() => ({}));
    const targetId = typeof body.user_id === "string" ? body.user_id : "";
    const next = typeof body.new_username === "string" ? body.new_username.trim().toLowerCase() : "";
    if (!targetId || !/^[a-z0-9][a-z0-9._-]{2,29}$/.test(next))
      return json({ error: "نام کاربری باید ۳ تا ۳۰ نویسه و فقط شامل حروف انگلیسی کوچک، عدد، نقطه، خط تیره یا زیرخط باشد." }, 400);

    const { data: target, error: targetError } = await admin.from("profiles")
      .select("user_id,username").eq("user_id", targetId).maybeSingle();
    if (targetError || !target) return json({ error: "کاربر موردنظر پیدا نشد." }, 404);
    if (target.username === next) return json({ success: true, username: next, unchanged: true });

    const { data: duplicate, error: duplicateError } = await admin.from("profiles")
      .select("user_id").ilike("username", next).neq("user_id", targetId).limit(1);
    if (duplicateError) return json({ error: "بررسی تکراری نبودن نام کاربری انجام نشد." }, 500);
    if (duplicate?.length) return json({ error: "این نام کاربری قبلاً استفاده شده است." }, 409);

    const { data: authResult, error: authReadError } = await admin.auth.admin.getUserById(targetId);
    if (authReadError || !authResult.user) return json({ error: "حساب ورود کاربر پیدا نشد." }, 404);
    const oldEmail = authResult.user.email || "";
    const oldMetadata = authResult.user.user_metadata || {};
    const { error: authUpdateError } = await admin.auth.admin.updateUserById(targetId, {
      email: `${next}@example.com`,
      email_confirm: true,
      user_metadata: { ...oldMetadata, username: next },
    });
    if (authUpdateError) return json({ error: authUpdateError.message }, 400);

    const { error: profileError } = await admin.from("profiles").update({ username: next }).eq("user_id", targetId);
    if (profileError) {
      const { error: rollbackError } = await admin.auth.admin.updateUserById(targetId, {
        email: oldEmail, email_confirm: true, user_metadata: oldMetadata,
      });
      return json({
        error: "به‌روزرسانی پروفایل انجام نشد. " + profileError.message +
          (rollbackError ? " بازگردانی شناسه ورود نیز نیاز به بررسی مدیر فنی دارد." : " شناسه ورود قبلی بازگردانده شد."),
      }, 500);
    }
    return json({ success: true, username: next });
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "خطای ناشناخته سرور" }, 500);
  }
});
