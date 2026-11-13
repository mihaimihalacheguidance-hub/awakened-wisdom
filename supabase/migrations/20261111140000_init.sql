-- Awakened Wisdom Lite: schema, RLS, circle RPCs, realtime authorization.
-- Every table is private by default; circles are reachable only with their invite code.

-- ───────── private data ─────────
create table public.user_state (
  user_id uuid primary key references auth.users on delete cascade,
  doc jsonb not null default '{}',
  updated_at timestamptz not null default now()
);
create table public.user_days (
  user_id uuid not null references auth.users on delete cascade,
  month text not null check (month ~ '^\d{4}-\d{2}$'),
  doc jsonb not null default '{}',
  updated_at timestamptz not null default now(),
  primary key (user_id, month)
);

-- ───────── circles ─────────
create table public.circles (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(name) between 1 and 60),
  code_hash text unique not null,   -- sha256 of the invite code; plaintext never stored
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now()
);
create table public.circle_members (
  circle_id uuid not null references public.circles on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  label text check (label is null or length(label) <= 60),
  shared jsonb not null default '{}',  -- filled only when the user turns sharing on
  marks jsonb not null default '{}',
  updated_at timestamptz not null default now(),
  primary key (circle_id, user_id)
);
create index circle_members_user_idx on public.circle_members (user_id);
create index circles_created_by_idx on public.circles (created_by);

create table public.join_attempts (   -- failed invite-code tries, for rate limiting
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users on delete cascade,
  at timestamptz not null default now()
);
create index join_attempts_user_at_idx on public.join_attempts (user_id, at);

create table public.feedback (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users on delete set null default auth.uid(),
  app_version text check (app_version is null or length(app_version) <= 40),
  kind text check (kind is null or length(kind) <= 40),
  body text not null check (length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index feedback_user_idx on public.feedback (user_id);

-- ───────── updated_at ─────────
create function public.touch() returns trigger
language plpgsql set search_path = '' as $$
begin new.updated_at := now(); return new; end $$;
create trigger touch_user_state before update on public.user_state for each row execute function public.touch();
create trigger touch_user_days before update on public.user_days for each row execute function public.touch();
create trigger touch_circle_members before update on public.circle_members for each row execute function public.touch();

-- ───────── helpers ─────────
create function public.is_member(cid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.circle_members m
                 where m.circle_id = cid and m.user_id = (select auth.uid()));
$$;

create function public.code_hash(code text) returns text
language sql immutable set search_path = '' as $$
  select encode(sha256(convert_to(lower(btrim(code)), 'UTF8')), 'hex');
$$;

-- ───────── RLS ─────────
alter table public.user_state enable row level security;
alter table public.user_days enable row level security;
alter table public.circles enable row level security;
alter table public.circle_members enable row level security;
alter table public.join_attempts enable row level security;
alter table public.feedback enable row level security;

create policy own_state on public.user_state for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy own_days on public.user_days for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create policy members_see_circle on public.circles for select to authenticated
  using (public.is_member(id));
create policy members_see_members on public.circle_members for select to authenticated
  using (public.is_member(circle_id));
create policy own_member_row on public.circle_members for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create policy send_feedback on public.feedback for insert to authenticated
  with check (user_id = (select auth.uid()));
-- join_attempts: no policies, reachable only from the RPCs below

-- ───────── grants: least privilege ─────────
revoke all on public.user_state, public.user_days, public.circles, public.circle_members,
              public.join_attempts, public.feedback from anon, authenticated;
grant select, insert, update, delete on public.user_state, public.user_days to authenticated;
grant select on public.circles to authenticated;
grant select on public.circle_members to authenticated;
grant update (label, shared, marks) on public.circle_members to authenticated;
grant insert (app_version, kind, body) on public.feedback to authenticated;

-- ───────── circle RPCs ─────────
-- Makes a 22-char code from a 32-letter alphabet (110 bits), stores only its hash,
-- adds the creator, and returns the code once.
create function public.create_circle(p_name text) returns json
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := auth.uid();
  a text := 'abcdefghijkmnpqrstuvwxyz23456789';
  b bytea; code text := ''; cid uuid; i int;
begin
  if uid is null then raise exception 'not signed in'; end if;
  p_name := btrim(coalesce(p_name, ''));
  if length(p_name) < 1 or length(p_name) > 60 then raise exception 'bad name'; end if;
  if (select count(*) from public.circles where created_by = uid
        and created_at > now() - interval '1 day') >= 10 then
    raise exception 'too many circles today';
  end if;
  -- random bytes from two v4 UUIDs, skipping the fixed version/variant bytes
  b := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  foreach i in array array[0,1,2,3,4,5,7,9,10,11,12,13,14,15,16,17,18,19,20,21,23,25] loop
    code := code || substr(a, (get_byte(b, i) % 32) + 1, 1);
  end loop;
  insert into public.circles (name, code_hash, created_by)
    values (p_name, public.code_hash(code), uid) returning id into cid;
  insert into public.circle_members (circle_id, user_id) values (cid, uid);
  return json_build_object('id', cid, 'code', code, 'name', p_name);
end $$;

-- Joins with an invite code. Wrong codes count against 10 tries per hour.
create function public.join_circle(p_code text) returns json
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); c record;
begin
  if uid is null then raise exception 'not signed in'; end if;
  if (select count(*) from public.join_attempts where user_id = uid
        and at > now() - interval '1 hour') >= 10 then
    raise exception 'too many tries, wait an hour';
  end if;
  select id, name into c from public.circles where code_hash = public.code_hash(p_code);
  if c.id is null then
    insert into public.join_attempts (user_id) values (uid);
    return null;
  end if;
  if not exists (select 1 from public.circle_members where circle_id = c.id and user_id = uid)
     and (select count(*) from public.circle_members where circle_id = c.id) >= 20 then
    raise exception 'circle is full';
  end if;
  insert into public.circle_members (circle_id, user_id) values (c.id, uid) on conflict do nothing;
  return json_build_object('id', c.id, 'name', c.name);
end $$;

-- Leaves a circle; the last member out deletes it.
create function public.leave_circle(p_circle uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'not signed in'; end if;
  delete from public.circle_members where circle_id = p_circle and user_id = uid;
  if not exists (select 1 from public.circle_members where circle_id = p_circle) then
    delete from public.circles where id = p_circle;
  end if;
end $$;

revoke execute on function public.is_member(uuid), public.create_circle(text),
  public.join_circle(text), public.leave_circle(uuid), public.code_hash(text), public.touch()
  from public, anon;
grant execute on function public.is_member(uuid), public.create_circle(text),
  public.join_circle(text), public.leave_circle(uuid) to authenticated;

-- ───────── realtime ─────────
-- Live updates of circle rows (RLS still applies to who receives them).
alter publication supabase_realtime add table public.circle_members;

-- Private channels named circle:<uuid> are open only to that circle's members.
create function public.can_use_topic(t text) returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  if t !~ '^circle:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return false; end if;
  return public.is_member(substr(t, 8)::uuid);
end $$;
revoke execute on function public.can_use_topic(text) from public, anon;
grant execute on function public.can_use_topic(text) to authenticated;

create policy circle_channel_read on realtime.messages for select to authenticated
  using (public.can_use_topic((select realtime.topic())));
create policy circle_channel_write on realtime.messages for insert to authenticated
  with check (public.can_use_topic((select realtime.topic())));
