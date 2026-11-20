begin;

alter table public.profiles
  add column if not exists start_date date;

grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
revoke update on public.profiles from authenticated;
grant update (grade, major, class_name, start_date) on public.profiles to authenticated;

drop policy if exists "profile self school update" on public.profiles;
create policy "profile self school update"
on public.profiles
for update
to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

create or replace function public.c90_guard_start_date()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_is_admin boolean := false;
begin
  if new.start_date is distinct from old.start_date then
    select exists (
      select 1 from public.profiles p
      where p.user_id = auth.uid() and p.role = 'admin'
    ) into v_is_admin;

    if not v_is_admin
       and not (old.start_date is null and new.start_date = current_date) then
      raise exception 'تغییر تاریخ شروع فقط برای مدیر مجاز است';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists c90_immutable_start_date on public.profiles;
create trigger c90_immutable_start_date
before update of start_date on public.profiles
for each row execute function public.c90_guard_start_date();

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
  set start_date = current_date
  where user_id = auth.uid()
    and start_date is null;

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

commit;