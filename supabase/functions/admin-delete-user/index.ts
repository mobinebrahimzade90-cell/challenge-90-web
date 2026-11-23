import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    if (!token) return json({ error: "نشست ورود معتبر نیست." }, 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!serviceKey) return json({ error: "تنظیمات امن سرور ناقص است." }, 500);

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "نشست ورود معتبر نیست." }, 401);

    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: actor, error: actorError } = await adminClient
      .from("profiles").select("role").eq("user_id", authData.user.id).maybeSingle();
    if (actorError || actor?.role !== "admin") {
      return json({ error: "فقط مدیر مجاز به حذف حساب است." }, 403);
    }

    const body = await req.json().catch(() => ({}));
    const targetId = typeof body.user_id === "string" ? body.user_id : "";
    const confirmUsername = typeof body.confirm_username === "string" ? body.confirm_username.trim() : "";
    if (!targetId || !confirmUsername) return json({ error: "اطلاعات تأیید حذف ناقص است." }, 400);
    if (targetId === authData.user.id) return json({ error: "حذف حساب مدیرِ واردشده از این پنل مجاز نیست." }, 400);

    const { data: target, error: targetError } = await adminClient
      .from("profiles").select("user_id, username, role").eq("user_id", targetId).maybeSingle();
    if (targetError || !target) return json({ error: "کاربر موردنظر پیدا نشد." }, 404);
    if (target.username !== confirmUsername) return json({ error: "نام کاربری برای تأیید با حساب انتخاب‌شده مطابقت ندارد." }, 400);

    if (target.role === "admin") {
      const { count, error: countError } = await adminClient
        .from("profiles").select("user_id", { count: "exact", head: true }).eq("role", "admin");
      if (countError) return json({ error: "امکان بررسی مدیران وجود ندارد." }, 500);
      if ((count ?? 0) <= 1) return json({ error: "آخرین حساب مدیر قابل حذف نیست." }, 400);
    }

    const { error: deleteError } = await adminClient.auth.admin.deleteUser(targetId);
    if (deleteError) return json({ error: deleteError.message }, 400);

    return json({ success: true, deleted_user_id: targetId });
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "خطای ناشناخته سرور" }, 500);
  }
});
