-- Challenge 90: repair profile schema and signup trigger
-- Run once in Supabase SQL Editor before registering users again.
begin;

alter table public.profiles
  add column if not exists username text,
  add column if not exists grade smallint,
  add column if not exists major text,
  add column if not exists class_name text,
  add column if not exists start_date date,
  add column if not exists initial_days integer;

create unique index if not exists profiles_username_lower_uidx
  on public.profiles (lower(username))
  where username is not null;

alter table public.profiles drop constraint if exists profiles_grade_check;
alter table public.profiles add constraint profiles_grade_check
  check (grade is null or grade in (10,11,12));

alter table public.profiles drop constraint if exists profiles_major_check;
alter table public.profiles add constraint profiles_major_check
  check (major is null or major in ('کامپیوتر','گرافیک','معماری'));

alter table public.profiles drop constraint if exists profiles_initial_days_check;
alter table public.profiles add constraint profiles_initial_days_check
  check (initial_days is null or initial_days between 0 and 90);

alter table public.profiles drop constraint if exists profiles_class_name_check;
alter table public.profiles add constraint profiles_class_name_check
  check (class_name is null or length(btrim(class_name)) between 1 and 40);

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_username text;
  v_display_name text;
  v_grade smallint;
  v_major text;
  v_class_name text;
begin
  v_username := lower(trim(coalesce(new.raw_user_meta_data->>'username', '')));
  v_display_name := nullif(trim(coalesce(new.raw_user_meta_data->>'display_name', '')), '');
  v_grade := nullif(new.raw_user_meta_data->>'grade', '')::smallint;
  v_major := nullif(trim(coalesce(new.raw_user_meta_data->>'major', '')), '');
  v_class_name := nullif(trim(coalesce(new.raw_user_meta_data->>'class_name', '')), '');

  if v_username = '' or v_username !~ '^[a-z0-9][a-z0-9._-]{2,29}$' then
    raise exception 'نام کاربری باید ۳ تا ۳۰ نویسه و فقط شامل حروف انگلیسی کوچک، عدد، نقطه، خط تیره یا زیرخط باشد';
  end if;
  if v_grade is not null and v_grade not in (10,11,12) then
    raise exception 'پایه تحصیلی نامعتبر است';
  end if;
  if v_major is not null and v_major not in ('کامپیوتر','گرافیک','معماری') then
    raise exception 'رشته تحصیلی نامعتبر است';
  end if;
  if v_class_name is not null and length(v_class_name) not between 1 and 40 then
    raise exception 'نام کلاس نامعتبر است';
  end if;

  insert into public.profiles
    (user_id, username, display_name, role, grade, major, class_name, start_date)
  values
    (new.id, v_username, coalesce(v_display_name, v_username), 'participant',
     v_grade, v_major, v_class_name, date '2026-11-21');

  return new;
end;
$$;

drop trigger if exists on_auth_user_created_90days on auth.users;
create trigger on_auth_user_created_90days
  after insert on auth.users
  for each row execute procedure public.handle_new_auth_user();

-- Repair any Auth account created earlier whose profile trigger failed.
insert into public.profiles
  (user_id, username, display_name, role, grade, major, class_name, start_date)
select
  u.id,
  lower(coalesce(nullif(trim(u.raw_user_meta_data->>'username'), ''), split_part(u.email, '@', 1))),
  coalesce(nullif(trim(u.raw_user_meta_data->>'display_name'), ''),
           nullif(trim(u.raw_user_meta_data->>'username'), ''),
           split_part(u.email, '@', 1)),
  'participant',
  case when u.raw_user_meta_data->>'grade' in ('10','11','12')
       then (u.raw_user_meta_data->>'grade')::smallint else null end,
  case when u.raw_user_meta_data->>'major' in ('کامپیوتر','گرافیک','معماری')
       then u.raw_user_meta_data->>'major' else null end,
  nullif(trim(u.raw_user_meta_data->>'class_name'), ''),
  date '2026-11-21'
from auth.users u
where not exists (
  select 1 from public.profiles p where p.user_id = u.id
)
on conflict (user_id) do nothing;

create or replace function public.c90_initialize_start_date()
returns date
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_date date;
begin
  if auth.uid() is null then
    raise exception 'ابتدا وارد حساب کاربری شو';
  end if;

  update public.profiles
  set start_date = date '2026-11-21'
  where user_id = auth.uid() and start_date is null;

  select start_date into v_date
  from public.profiles
  where user_id = auth.uid();

  if v_date is null then
    raise exception 'پروفایل حساب پیدا نشد';
  end if;
  return v_date;
end;
$$;

revoke all on function public.c90_initialize_start_date() from public;
grant execute on function public.c90_initialize_start_date() to authenticated;

create or replace function public.c90_set_initial_days(p_days integer)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
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
  where user_id = auth.uid() and initial_days is null
  returning initial_days into v_days;

  if found then
    v_saved := true;
  else
    select initial_days into v_days
    from public.profiles where user_id = auth.uid();
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
$$;

revoke all on function public.c90_set_initial_days(integer) from public;
grant execute on function public.c90_set_initial_days(integer) to authenticated;

grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
revoke update on public.profiles from authenticated;
grant update (grade, major, class_name) on public.profiles to authenticated;

drop policy if exists "profile self school update" on public.profiles;
create policy "profile self school update"
on public.profiles for update to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

commit;
