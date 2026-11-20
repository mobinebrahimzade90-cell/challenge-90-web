alter table public.profiles
  add column if not exists initial_days integer;

alter table public.profiles
  drop constraint if exists profiles_initial_days_check;

alter table public.profiles
  add constraint profiles_initial_days_check
  check (initial_days is null or initial_days between 0 and 90);

create or replace function public.c90_set_initial_days(p_days integer)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $c90_initial_days$
declare
  v_days integer;
  v_saved boolean := false;
begin
  if auth.uid() is null then
    raise exception 'ابتدا وارد حساب کاربری شو';
  end if;

  if p_days is null or p_days < 0 or p_days > 90 then
    raise exception 'تعداد روز باید عددی بین صفر تا ۹۰ باشد';
  end if;

  update public.profiles
  set initial_days = p_days
  where user_id = auth.uid()
    and initial_days is null
  returning initial_days into v_days;

  if found then
    v_saved := true;
  else
    select initial_days into v_days
    from public.profiles
    where user_id = auth.uid();
  end if;

  if v_days is null then
    raise exception 'ذخیره تعداد روزها انجام نشد';
  end if;

  return jsonb_build_object(
    'initial_days', v_days,
    'bonus_points', v_days * 10,
    'saved_now', v_saved
  );
end;
$c90_initial_days$;

revoke all on function public.c90_set_initial_days(integer) from public;
grant execute on function public.c90_set_initial_days(integer) to authenticated;
