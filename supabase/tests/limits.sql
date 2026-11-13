-- Size and feedback limits. Ends with RAISE, so everything is rolled back.
do $$
declare a uuid:=gen_random_uuid(); r text:=''; i int; j json; cid uuid;
begin
  insert into auth.users(id, instance_id, aud, role, email) values
    (a,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','lim-a@test.invalid');
  execute 'set local role authenticated';
  perform set_config('request.jwt.claims', json_build_object('sub',a,'role','authenticated')::text, true);
  insert into public.user_state(user_id,doc) values (a, json_build_object('j', repeat('x', 1000))::jsonb);
  r := r || 'state_small=ok';
  begin update public.user_state set doc = json_build_object('j', repeat('x', 600000))::jsonb where user_id=a;
    r := r || ' state_huge=ALLOWED'; exception when check_violation then r := r || ' state_huge=blocked'; end;
  begin insert into public.user_days(user_id,month,doc) values (a,'2026-11', json_build_object('j', repeat('x', 300000))::jsonb);
    r := r || ' days_huge=ALLOWED'; exception when check_violation then r := r || ' days_huge=blocked'; end;
  j := public.create_circle('Limit circle'); cid := (j->>'id')::uuid;
  begin update public.circle_members set shared = json_build_object('j', repeat('x', 20000))::jsonb where user_id=a;
    r := r || ' shared_huge=ALLOWED'; exception when check_violation then r := r || ' shared_huge=blocked'; end;
  update public.circle_members set shared = '{"focus":"ok"}' where user_id=a; r := r || ' shared_small=ok';
  for i in 1..20 loop insert into public.feedback(kind, body) values ('t', 'msg ' || i); end loop;
  r := r || ' feedback_20=ok';
  begin insert into public.feedback(kind, body) values ('t', 'msg 21'); r := r || ' feedback_21=ALLOWED';
  exception when others then r := r || ' feedback_21=blocked'; end;
  raise exception 'RESULT %', r;
end $$;
