-- Challenge 90 security/data-integrity hardening.
-- Apply once in Supabase SQL Editor after the existing setup migrations.
-- Does not delete existing user or report rows.

begin;

create or replace function public.c90_valid_day_map(p_map jsonb, p_max_day integer)
returns jsonb
language sql
immutable
set search_path = pg_catalog
as $c90_day_map$
  select coalesce(
    jsonb_object_agg(
      e.key,
      case
        when jsonb_typeof(e.value) = 'object' then
          jsonb_set(
            jsonb_set(
              e.value,
              '{tasks}',
              coalesce((
                select jsonb_agg(t.value order by t.ordinality)
                from jsonb_array_elements(
                  case
                    when jsonb_typeof(e.value->'tasks') = 'array'
                    then e.value->'tasks'
                    else '[]'::jsonb
                  end
                ) with ordinality as t(value, ordinality)
                where t.ordinality <= 50
              ), '[]'::jsonb),
              true
            ),
            '{min}',
            to_jsonb(
              case
                when coalesce(e.value->>'min', '') ~ '^[0-9]{1,3}$'
                 and (e.value->>'min')::integer <= 180
                then (e.value->>'min')::integer
                else 0
              end
            ),
            true
          )
        else '{}'::jsonb
      end
    ),
    '{}'::jsonb
  )
  from jsonb_each(
    case when jsonb_typeof(p_map) = 'object'
      then p_map else '{}'::jsonb end
  ) as e(key, value)
  where length(e.key) <= 2
    and e.key ~ '^[1-9][0-9]?$'
    and e.key::integer between 1 and greatest(1, least(coalesce(p_max_day, 90), 90))
$c90_day_map$;
revoke all on function public.c90_valid_day_map(jsonb, integer) from public;
grant execute on function public.c90_valid_day_map(jsonb, integer) to authenticated;

create or replace function public.c90_safe_date(p_value text)
returns date language plpgsql immutable set search_path = pg_catalog
as $c90_safe_date$
begin
  if p_value is null or p_value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then return null; end if;
  return p_value::date;
exception when others then return null;
end;
$c90_safe_date$;
revoke all on function public.c90_safe_date(text) from public;
grant execute on function public.c90_safe_date(text) to authenticated;

-- New profiles use the server date. Existing profiles are not reset.
create or replace function public.handle_new_auth_user()
returns trigger language plpgsql security definer
set search_path = public, pg_temp set row_security = off
as $c90_signup_hardened$
declare
  v_username text;
  v_display_name text;
  v_grade smallint;
  v_major text;
  v_class_name text;
begin
  v_username := lower(btrim(coalesce(new.raw_user_meta_data->>'username', '')));
  v_display_name := nullif(btrim(coalesce(new.raw_user_meta_data->>'display_name', '')), '');
  v_grade := nullif(new.raw_user_meta_data->>'grade', '')::smallint;
  v_major := nullif(btrim(coalesce(new.raw_user_meta_data->>'major', '')), '');
  v_class_name := nullif(btrim(coalesce(new.raw_user_meta_data->>'class_name', '')), '');
  if v_username = '' or v_username !~ '^[a-z0-9][a-z0-9._-]{2,29}$' then raise exception 'نام کاربری نامعتبر است'; end if;
  if v_grade is not null and v_grade not in (10,11,12) then raise exception 'پایه تحصیلی نامعتبر است'; end if;
  if v_major is not null and v_major not in ('کامپیوتر','گرافیک','معماری') then raise exception 'رشته تحصیلی نامعتبر است'; end if;
  if v_class_name is not null and length(v_class_name) not between 1 and 40 then raise exception 'نام کلاس نامعتبر است'; end if;
  insert into public.profiles(user_id,username,display_name,role,grade,major,class_name,start_date)
  values(new.id,v_username,coalesce(v_display_name,v_username),'participant',v_grade,v_major,v_class_name,current_date);
  return new;
end;
$c90_signup_hardened$;
drop trigger if exists on_auth_user_created_90days on auth.users;
create trigger on_auth_user_created_90days after insert on auth.users
for each row execute function public.handle_new_auth_user();

create or replace function public.c90_guard_start_date()
returns trigger language plpgsql security definer
set search_path = public, pg_temp set row_security = off
as $c90_guard$
declare v_is_admin boolean := false;
begin
  if new.start_date is distinct from old.start_date then
    select exists(select 1 from public.profiles p where p.user_id=auth.uid() and p.role='admin') into v_is_admin;
    if not v_is_admin and not (
      auth.uid() is not null and auth.uid()=old.user_id
      and old.start_date is null and new.start_date=current_date
    ) then raise exception 'تغییر تاریخ شروع فقط برای مدیر مجاز است'; end if;
  end if;
  return new;
end;
$c90_guard$;
drop trigger if exists c90_immutable_start_date on public.profiles;
create trigger c90_immutable_start_date before update of start_date on public.profiles
for each row execute function public.c90_guard_start_date();

revoke update on public.profiles from authenticated;
grant update (grade, major, class_name) on public.profiles to authenticated;

create or replace function public.c90_initialize_start_date()
returns date language plpgsql security definer
set search_path = public, pg_temp set row_security = off
as $c90_init_date$
declare v_date date;
begin
  if auth.uid() is null then raise exception 'ابتدا وارد حساب کاربری شو'; end if;
  update public.profiles set start_date=current_date where user_id=auth.uid() and start_date is null;
  select start_date into v_date from public.profiles where user_id=auth.uid();
  if v_date is null then raise exception 'پروفایل حساب پیدا نشد'; end if;
  return v_date;
end;
$c90_init_date$;
revoke all on function public.c90_initialize_start_date() from public;
grant execute on function public.c90_initialize_start_date() to authenticated;

create or replace function public.c90_admin_set_start_date(p_user_id uuid,p_start_date date)
returns date language plpgsql security definer
set search_path = public, pg_temp set row_security = off
as $c90_admin_date$
begin
  if auth.uid() is null or not exists(select 1 from public.profiles where user_id=auth.uid() and role='admin') then
    raise exception 'فقط مدیر مجاز به تغییر تاریخ شروع است';
  end if;
  if p_user_id is null or p_start_date is null or p_start_date<date '2000-01-01' or p_start_date>current_date then
    raise exception 'تاریخ شروع انتخاب‌شده معتبر نیست';
  end if;
  update public.profiles set start_date=p_start_date where user_id=p_user_id;
  if not found then raise exception 'حساب کاربر پیدا نشد'; end if;
  insert into public.daily_reports as dr(user_id,report_date,payload,updated_at)
  values(p_user_id,date '2000-01-01',jsonb_build_object('start',p_start_date::text,'days','{}'::jsonb,'hyp',jsonb_build_object('days','{}'::jsonb)),now())
  on conflict(user_id,report_date) do update
  set payload=jsonb_set(coalesce(dr.payload,'{}'::jsonb),'{start}',to_jsonb(p_start_date::text),true),updated_at=now();
  return p_start_date;
end;
$c90_admin_date$;
revoke all on function public.c90_admin_set_start_date(uuid,date) from public;
grant execute on function public.c90_admin_set_start_date(uuid,date) to authenticated;

drop function if exists public.class_ranking();
create function public.class_ranking()
returns table (
  class_name text,
  member_count integer,
  active_count integer,
  average_daily_points numeric,
  participation_pct numeric,
  consistency_pct numeric,
  ranking_score numeric,
  is_my_class boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $c90_ranking$
declare
  v_grade smallint;
  v_major text;
  v_class text;
begin
  if auth.uid() is null then
    raise exception 'برای مشاهده رتبه‌بندی ابتدا وارد حساب شو';
  end if;

  select p.grade, p.major, p.class_name
    into v_grade, v_major, v_class
  from public.profiles as p
  where p.user_id = auth.uid();

  if v_grade is null or v_major is null then
    raise exception 'پایه و رشته تحصیلی حساب کامل نیست';
  end if;

  if v_class is null or btrim(v_class) = '' then
    raise exception 'نام کلاس را در بخش حساب کاربری ثبت کن';
  end if;

  return query
  with cohort as (
    select p.user_id, p.class_name, coalesce(p.initial_days, 0) as initial_days, p.start_date
    from public.profiles as p
    where p.grade = v_grade
      and p.major = v_major
      and p.class_name is not null
      and btrim(p.class_name) <> ''
  ),
  report_data as (
    select c.user_id, c.class_name, c.initial_days, c.start_date, dr.payload
    from cohort as c
    left join public.daily_reports as dr
      on dr.user_id = c.user_id
     and dr.report_date = date '2000-01-01'
  ),
  per_user as (
    select
      rd.user_id,
      rd.class_name,
      coalesce(st.clean_days, 0)::numeric as clean_days,
      coalesce(st.active_days, 0)::numeric as active_days,
      greatest(
        0::numeric,
        coalesce(st.clean_days, 0)::numeric * 100
        - coalesce(st.fail_days, 0)::numeric * 150
        + coalesce(st.tasks_done, 0)::numeric * 5
        - coalesce(st.tasks_missed, 0)::numeric * 2
        + coalesce(hy.sessions_done, 0)::numeric * 10
        + floor(coalesce(hy.minutes_done, 0)::numeric / 5)
        + coalesce(rd.initial_days, 0)::numeric * 10
      ) as points,
      greatest(
        1::numeric,
        least(
          90::numeric,
          coalesce(
            (current_date - rd.start_date + 1)::numeric,
            1::numeric
          )
        )
      ) as elapsed_days
    from report_data as rd
    left join lateral (
      select
        count(*) filter (where d.value->>'st' = 'clean')::integer as clean_days,
        count(*) filter (where d.value->>'st' = 'fail')::integer as fail_days,
        count(*) filter (
          where d.value->>'st' in ('clean', 'fail')
             or (
               case
                 when jsonb_typeof(d.value->'tasks') = 'array'
                 then jsonb_array_length(d.value->'tasks')
                 else 0
               end
             ) > 0
             or nullif(btrim(d.value->>'pray'), '') is not null
             or nullif(btrim(d.value->>'how'), '') is not null
             or nullif(btrim(d.value->>'pos'), '') is not null
             or nullif(btrim(d.value->>'why'), '') is not null
        )::integer as active_days,
        coalesce(sum((
          select count(*)
          from jsonb_array_elements(
            case
              when jsonb_typeof(d.value->'tasks') = 'array'
              then d.value->'tasks'
              else '[]'::jsonb
            end
          ) as task(value)
          where coalesce(
            task.value->>'s',
            case when task.value->>'d' = 'true' then 'y' else '' end
          ) = 'y'
        )), 0)::integer as tasks_done,
        coalesce(sum((
          select count(*)
          from jsonb_array_elements(
            case
              when jsonb_typeof(d.value->'tasks') = 'array'
              then d.value->'tasks'
              else '[]'::jsonb
            end
          ) as task(value)
          where coalesce(
            task.value->>'s',
            case when task.value->>'d' = 'true' then 'y' else '' end
          ) = 'n'
        )), 0)::integer as tasks_missed
      from jsonb_each(public.c90_valid_day_map(rd.payload->'days', least(90, greatest(1, coalesce(current_date - rd.start_date + 1, 1))::integer))) as d(key, value)
    ) as st on true
    left join lateral (
      select
        count(*) filter (where h.value->>'st' = 'done')::integer as sessions_done,
        coalesce(sum(
          case
            when h.value->>'st' = 'done'
             and coalesce(h.value->>'min', '') ~ '^[0-9]+$'
            then greatest(0, (h.value->>'min')::integer)
            else 0
          end
        ), 0)::integer as minutes_done
      from jsonb_each(public.c90_valid_day_map(rd.payload->'hyp'->'days', 20)) as h(key, value)
    ) as hy on true
  ),
  class_stats as (
    select
      pu.class_name,
      count(*)::integer as member_count,
      count(*) filter (where pu.active_days > 0)::integer as active_count,
      avg(least(100::numeric, greatest(0::numeric, pu.points / pu.elapsed_days))) as average_daily_points,
      avg(least(100::numeric, greatest(0::numeric, pu.clean_days / pu.elapsed_days * 100))) as consistency_pct
    from per_user as pu
    group by pu.class_name
  )
  select
    cs.class_name::text,
    cs.member_count,
    cs.active_count,
    round(cs.average_daily_points, 2),
    round(cs.active_count::numeric * 100 / nullif(cs.member_count, 0), 2),
    round(cs.consistency_pct, 2),
    round(
      cs.average_daily_points * 0.50
      + (cs.active_count::numeric * 100 / nullif(cs.member_count, 0)) * 0.30
      + cs.consistency_pct * 0.20,
      2
    ),
    (cs.class_name = v_class)
  from class_stats as cs
  order by 7 desc, 1 asc;
end;
$c90_ranking$;
revoke all on function public.class_ranking() from public;
grant execute on function public.class_ranking() to authenticated;
drop function if exists public.individual_ranking();
-- Challenge 90: individual ranking RPC
-- Run once AFTER realtime_class_ranking.sql.
-- Does not alter or delete user data.

-- 9. Individual leaderboard for users in the same grade and major.
-- Scores follow the app's personal score formula.
drop function if exists public.individual_ranking();

create function public.individual_ranking()
returns table (
  rank_no integer,
  username text,
  display_name text,
  points numeric,
  is_me boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $c90_individual$
declare
  v_grade smallint;
  v_major text;
begin
  if auth.uid() is null then
    raise exception 'ابتدا وارد حساب کاربری شو';
  end if;

  select p.grade, p.major
    into v_grade, v_major
  from public.profiles p
  where p.user_id = auth.uid();

  if v_grade is null or v_major is null then
    raise exception 'پایه و رشته تحصیلی حساب کامل نیست';
  end if;

  return query
  with cohort as (
    select p.user_id, p.username, p.display_name, coalesce(p.initial_days, 0) as initial_days, p.start_date
    from public.profiles p
    where p.grade = v_grade and p.major = v_major
  ),
  reports as (
    select c.user_id, c.username, c.display_name, c.initial_days, c.start_date, dr.payload
    from cohort c
    left join public.daily_reports dr
      on dr.user_id = c.user_id
     and dr.report_date = date '2000-01-01'
  ),
  scores as (
    select
      r.user_id, r.username, r.display_name,
      greatest(
        0::numeric,
        coalesce(d.clean_days, 0)::numeric * 100
        - coalesce(d.fail_days, 0)::numeric * 150
        + coalesce(d.tasks_done, 0)::numeric * 5
        - coalesce(d.tasks_missed, 0)::numeric * 2
        + coalesce(h.sessions_done, 0)::numeric * 10
        + floor(coalesce(h.minutes_done, 0)::numeric / 5)
        + coalesce(r.initial_days, 0)::numeric * 10
      ) as score
    from reports r
    left join lateral (
      select
        count(*) filter (where x.value->>'st' = 'clean') as clean_days,
        count(*) filter (where x.value->>'st' = 'fail') as fail_days,
        coalesce(sum((
          select count(*)
          from jsonb_array_elements(
            case when jsonb_typeof(x.value->'tasks') = 'array'
              then x.value->'tasks' else '[]'::jsonb end
          ) task(value)
          where coalesce(task.value->>'s',
            case when task.value->>'d' = 'true' then 'y' else '' end) = 'y'
        )), 0) as tasks_done,
        coalesce(sum((
          select count(*)
          from jsonb_array_elements(
            case when jsonb_typeof(x.value->'tasks') = 'array'
              then x.value->'tasks' else '[]'::jsonb end
          ) task(value)
          where coalesce(task.value->>'s',
            case when task.value->>'d' = 'true' then 'y' else '' end) = 'n'
        )), 0) as tasks_missed
      from jsonb_each(public.c90_valid_day_map(r.payload->'days', least(90, greatest(1, coalesce(current_date - r.start_date + 1, 1))::integer))) x(key, value)
    ) d on true
    left join lateral (
      select
        count(*) filter (where x.value->>'st' = 'done') as sessions_done,
        coalesce(sum(
          case when x.value->>'st' = 'done'
            and coalesce(x.value->>'min', '') ~ '^[0-9]+$'
            then greatest(0, (x.value->>'min')::integer)
            else 0 end
        ), 0) as minutes_done
      from jsonb_each(public.c90_valid_day_map(r.payload->'hyp'->'days', 20)) x(key, value)
    ) h on true
  )
  select
    row_number() over (order by s.score desc, s.username asc)::integer,
    s.username::text,
    s.display_name::text,
    s.score,
    s.user_id = auth.uid()
  from scores s
  order by s.score desc, s.username asc;
end;
$c90_individual$;
revoke all on function public.individual_ranking() from public;
grant execute on function public.individual_ranking() to authenticated;

commit;
