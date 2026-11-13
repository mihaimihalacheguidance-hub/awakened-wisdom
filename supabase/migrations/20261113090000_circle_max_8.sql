-- Circles are meant for three to eight people (the app says so); cap joins at 8.
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
     and (select count(*) from public.circle_members where circle_id = c.id) >= 8 then
    raise exception 'circle is full';
  end if;
  insert into public.circle_members (circle_id, user_id) values (c.id, uid) on conflict do nothing;
  return json_build_object('id', c.id, 'name', c.name);
end $$;
