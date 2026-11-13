-- Two-user RLS test. Ends with RAISE, so every write (test users included) is rolled back.
-- Expected: B sees 0 of A's rows, can't write as A, joins only with the code, anon is blocked.
do $$
declare a uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); r text:=''; n int; j json; code text; cid uuid;
begin
  insert into auth.users(id, instance_id, aud, role, email) values
    (a,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','rls-a@test.invalid'),
    (b,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','rls-b@test.invalid');
  execute 'set local role authenticated';
  -- user A
  perform set_config('request.jwt.claims', json_build_object('sub',a,'role','authenticated')::text, true);
  insert into public.user_state(user_id,doc) values (a,'{"x":1}');
  insert into public.user_days(user_id,month,doc) values (a,'2026-11','{"2026-11-11":{}}');
  j := public.create_circle('Test circle'); code := j->>'code'; cid := (j->>'id')::uuid;
  r := r || 'codeLen=' || length(code);
  select count(*) into n from public.user_state; r := r || ' A_state=' || n;
  -- user B
  perform set_config('request.jwt.claims', json_build_object('sub',b,'role','authenticated')::text, true);
  select count(*) into n from public.user_state; r := r || ' B_sees_state=' || n;
  select count(*) into n from public.user_days; r := r || ' B_sees_days=' || n;
  select count(*) into n from public.circles; r := r || ' B_sees_circles_before=' || n;
  select count(*) into n from public.circle_members; r := r || ' B_sees_members_before=' || n;
  begin insert into public.user_state(user_id,doc) values (a,'{}'); r := r || ' B_insert_as_A=ALLOWED';
  exception when others then r := r || ' B_insert_as_A=blocked'; end;
  update public.user_state set doc='{"hacked":1}' where user_id=a; get diagnostics n = row_count; r := r || ' B_update_A=' || n;
  delete from public.user_days where user_id=a; get diagnostics n = row_count; r := r || ' B_delete_A_days=' || n;
  r := r || ' wrongCode=' || coalesce(public.join_circle('nope-nope')::text,'null');
  j := public.join_circle(upper(code)); r := r || ' joined=' || (j->>'id' = cid::text);
  select count(*) into n from public.circle_members; r := r || ' B_sees_members_after=' || n;
  update public.circle_members set label='x' where user_id=a; get diagnostics n = row_count; r := r || ' B_update_A_member=' || n;
  update public.circle_members set label='me', shared='{"run":3}' where user_id=b; get diagnostics n = row_count; r := r || ' B_update_own=' || n;
  begin update public.circle_members set user_id=b where user_id=b; r := r || ' B_change_user_id=ALLOWED';
  exception when others then r := r || ' B_change_user_id=blocked'; end;
  begin insert into public.circle_members(circle_id,user_id) values (cid,b); r := r || ' direct_member_insert=ALLOWED';
  exception when others then r := r || ' direct_member_insert=blocked'; end;
  insert into public.feedback(body,app_version) values ('test','0.1.0-lite'); r := r || ' feedback_insert=ok';
  begin select count(*) into n from public.feedback; r := r || ' feedback_read=ALLOWED';
  exception when others then r := r || ' feedback_read=blocked'; end;
  r := r || ' topic_ok=' || private.can_use_topic('circle:'||cid) || ' topic_bad=' || private.can_use_topic('circle:x');
  perform public.leave_circle(cid);
  select count(*) into n from public.circles; r := r || ' B_sees_circles_after_leave=' || n;
  -- anonymous (not signed in)
  execute 'set local role anon';
  begin select count(*) into n from public.user_state; r := r || ' anon_read=ALLOWED';
  exception when others then r := r || ' anon_read=blocked'; end;
  begin perform public.create_circle('x'); r := r || ' anon_rpc=ALLOWED';
  exception when others then r := r || ' anon_rpc=blocked'; end;
  raise exception 'RESULT %', r;
end $$;
