-- FileVow: Supabase schema for cloud sign-in and the active-user count.
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- (Or with the Supabase CLI: supabase db push.)
--
-- Supabase Auth already stores the accounts themselves (auth.users: id, e-mail, sign-up
-- and last sign-in times). This adds one row per account per day the app is used, and
-- the two functions the app is allowed to call. Nothing about files is ever stored.

-- ---------------------------------------------------------------- daily activity

create table if not exists public.app_activity (
  user_id     uuid not null references auth.users (id) on delete cascade,
  day         date not null default (now() at time zone 'utc')::date,
  app_version text not null,
  os_name     text,
  primary key (user_id, day)
);

comment on table public.app_activity is
  'One row per FileVow account per day it was used. Written only through record_activity().';

-- Row-level security with no policies: the public (anon) key and signed-in users cannot
-- read or write this table directly. Only the functions below and the dashboard can.
alter table public.app_activity enable row level security;
revoke all on public.app_activity from anon, authenticated;

create index if not exists app_activity_day_idx on public.app_activity (day);

-- ---------------------------------------------------------------- functions the app calls

create or replace function public.record_activity(app_version text, os_name text default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in' using errcode = '42501';
  end if;
  insert into public.app_activity (user_id, day, app_version, os_name)
  values (auth.uid(), (now() at time zone 'utc')::date, left(app_version, 32), left(os_name, 64))
  on conflict (user_id, day) do update
    set app_version = excluded.app_version, os_name = excluded.os_name;
end;
$$;

create or replace function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in' using errcode = '42501';
  end if;
  -- Removes the account; app_activity rows go with it (on delete cascade).
  delete from auth.users where id = auth.uid();
end;
$$;

revoke all on function public.record_activity(text, text) from public, anon;
revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.record_activity(text, text) to authenticated;
grant execute on function public.delete_my_account() to authenticated;

-- ---------------------------------------------------------------- your numbers
-- Views for the dashboard owner. They run with the caller's rights (security_invoker),
-- and anon/authenticated have no access, so only you see them (Table Editor / SQL Editor).

create or replace view public.usage_summary
with (security_invoker = true) as
select
  (select count(*) from auth.users)                                                  as total_accounts,
  (select count(*) from auth.users where created_at >= now() - interval '30 days')   as new_accounts_30d,
  (select count(distinct user_id) from public.app_activity
     where day = (now() at time zone 'utc')::date)                                   as active_today,
  (select count(distinct user_id) from public.app_activity
     where day > (now() at time zone 'utc')::date - 7)                               as active_7d,
  (select count(distinct user_id) from public.app_activity
     where day > (now() at time zone 'utc')::date - 30)                              as active_30d;

create or replace view public.daily_active_users
with (security_invoker = true) as
select day, count(distinct user_id) as active_accounts
from public.app_activity
group by day
order by day desc;

create or replace view public.active_by_version
with (security_invoker = true) as
select app_version, count(distinct user_id) as accounts_last_30d
from public.app_activity
where day > (now() at time zone 'utc')::date - 30
group by app_version
order by accounts_last_30d desc;

revoke all on public.usage_summary, public.daily_active_users, public.active_by_version from anon, authenticated;
