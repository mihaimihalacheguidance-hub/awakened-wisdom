-- Upper bounds on what one account can store or push to a circle, far above normal use.
alter table public.user_state add constraint user_state_doc_size check (octet_length(doc::text) <= 524288);
alter table public.user_days add constraint user_days_doc_size check (octet_length(doc::text) <= 262144);
alter table public.circle_members add constraint circle_members_shared_size
  check (shared is null or octet_length(shared::text) <= 16384);
alter table public.circle_members add constraint circle_members_marks_size
  check (marks is null or octet_length(marks::text) <= 24576);

-- At most 20 feedback messages per account per day.
create function private.feedback_rate() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.user_id is not null and (select count(*) from public.feedback
       where user_id = new.user_id and created_at > now() - interval '1 day') >= 20 then
    raise exception 'too much feedback today';
  end if;
  return new;
end $$;
revoke execute on function private.feedback_rate() from public, anon, authenticated;

create trigger feedback_rate before insert on public.feedback
  for each row execute function private.feedback_rate();
