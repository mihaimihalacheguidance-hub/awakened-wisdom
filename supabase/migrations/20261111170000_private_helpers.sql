-- Move policy helpers out of the exposed API schema, so they have no /rpc endpoint.
-- Only create_circle, join_circle and leave_circle stay callable by signed-in users.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

alter function public.is_member(uuid) set schema private;
alter function public.can_use_topic(text) set schema private;
alter function public.code_hash(text) set schema private;

-- bodies that referenced the old locations (same signatures, so policies keep pointing here)
create or replace function private.can_use_topic(t text) returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  if t !~ '^circle:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return false; end if;
  return private.is_member(substr(t, 8)::uuid);
end $$;

create or replace function public.create_circle(p_name text) returns json
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
  b := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  foreach i in array array[0,1,2,3,4,5,7,9,10,11,12,13,14,15,16,17,18,19,20,21,23,25] loop
    code := code || substr(a, (get_byte(b, i) % 32) + 1, 1);
  end loop;
  insert into public.circles (name, code_hash, created_by)
    values (p_name, private.code_hash(code), uid) returning id into cid;
  insert into public.circle_members (circle_id, user_id) values (cid, uid);
  return json_build_object('id', cid, 'code', code, 'name', p_name);
end $$;

create or replace function public.join_circle(p_code text) returns json
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); c record;
begin
  if uid is null then raise exception 'not signed in'; end if;
  if (select count(*) from public.join_attempts where user_id = uid
        and at > now() - interval '1 hour') >= 10 then
    raise exception 'too many tries, wait an hour';
  end if;
  select id, name into c from public.circles where code_hash = private.code_hash(p_code);
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
