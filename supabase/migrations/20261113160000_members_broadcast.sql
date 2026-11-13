-- postgres_changes does not apply RLS to DELETE events, so every subscriber saw
-- {circle_id, user_id} of every leave. Member changes now go out as a broadcast
-- on the circle's private channel, which only its members can read.
alter publication supabase_realtime drop table public.circle_members;

create function private.members_changed() returns trigger
language plpgsql security definer set search_path = '' as $$
declare cid uuid := coalesce(new.circle_id, old.circle_id);
begin
  perform realtime.send('{}'::jsonb, 'members', 'circle:' || cid::text, true);
  return null;
end $$;
revoke execute on function private.members_changed() from public, anon, authenticated;

create trigger circle_members_changed
  after insert or update or delete on public.circle_members
  for each row execute function private.members_changed();

-- join_circle: serialise per user (try limit) and per circle (member cap)
create or replace function public.join_circle(p_code text) returns json
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); c record;
begin
  if uid is null then raise exception 'not signed in'; end if;
  perform pg_advisory_xact_lock(hashtext('join:' || uid::text));
  if (select count(*) from public.join_attempts where user_id = uid
        and at > now() - interval '1 hour') >= 10 then
    raise exception 'too many tries, wait an hour';
  end if;
  select id, name into c from public.circles where code_hash = private.code_hash(p_code) for update;
  if c.id is null then
    insert into public.join_attempts (user_id) values (uid);
    return null;
  end if;
  if not exists (select 1 from public.circle_members where circle_id = c.id and user_id = uid)
     and (select count(*) from public.circle_members where circle_id = c.id) >= 8 then
    raise exception 'circle is full';
  end if;
  insert into public.circle_members (circle_id, user_id) values (c.id, uid) on conflict do nothing;
  return json_build_object('id', c.id, 'name', c.name);
end $$;
