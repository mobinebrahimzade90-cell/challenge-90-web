-- ستون نام مستعار مدیریتی؛ username و display_name اصلی تغییر نمی‌کنند
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS admin_alias TEXT;

COMMENT ON COLUMN public.profiles.admin_alias IS
'نام مستعار داخلی برای نمایش و جست‌وجو در پنل مدیریت';

CREATE OR REPLACE FUNCTION public.admin_set_user_alias(
  p_target_user_id UUID,
  p_alias TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET row_security = off
AS $$
DECLARE
  v_alias TEXT := NULLIF(BTRIM(COALESCE(p_alias, '')), '');
  v_is_admin BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.user_id = auth.uid() AND p.role = 'admin'
  ) INTO v_is_admin;

  IF NOT v_is_admin THEN
    RAISE EXCEPTION 'فقط مدیر مجاز به تغییر نام نمایشی است';
  END IF;

  IF LENGTH(COALESCE(v_alias, '')) > 40 THEN
    RAISE EXCEPTION 'نام نمایشی حداکثر ۴۰ نویسه باشد';
  END IF;

  UPDATE public.profiles
  SET admin_alias = v_alias
  WHERE user_id = p_target_user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'کاربر موردنظر پیدا نشد';
  END IF;

  RETURN COALESCE(v_alias, '');
END;
$$;

REVOKE ALL ON FUNCTION public.admin_set_user_alias(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.admin_set_user_alias(UUID, TEXT) FROM anon;
GRANT EXECUTE ON FUNCTION public.admin_set_user_alias(UUID, TEXT) TO authenticated;
