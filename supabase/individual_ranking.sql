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
    select p.user_id, p.username, p.display_name, coalesce(p.initial_days, 0) as initial_days
    from public.profiles p
    where p.grade = v_grade and p.major = v_major
  ),
  reports as (
    select c.user_id, c.username, c.display_name, c.initial_days, dr.payload
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
      from jsonb_each(
        case when jsonb_typeof(r.payload->'days') = 'object'
          then r.payload->'days' else '{}'::jsonb end
      ) x(key, value)
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
      from jsonb_each(
        case when jsonb_typeof(r.payload->'hyp'->'days') = 'object'
          then r.payload->'hyp'->'days' else '{}'::jsonb end
      ) x(key, value)
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


