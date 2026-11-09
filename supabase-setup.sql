-- Run once in the dedicated project's SQL editor. No student data is in this file.
create table public.earth_teachers(user_id uuid primary key references auth.users(id) on delete cascade);
alter table public.earth_teachers enable row level security;
create policy teacher_self on public.earth_teachers for select to authenticated using(user_id=(select auth.uid()));
revoke all on public.earth_teachers from anon, authenticated;
grant select on public.earth_teachers to authenticated;

create table public.earth_classes(
 id uuid primary key default gen_random_uuid(),
 teacher_id uuid not null references auth.users(id),
 title text not null check(length(trim(title)) between 1 and 60),
 code text not null unique default substring(replace(gen_random_uuid()::text,'-',''),1,12),
 accepting boolean not null default true,
 created_at timestamptz not null default now()
);
alter table public.earth_classes enable row level security;
create policy own_classes on public.earth_classes for all to authenticated
 using(teacher_id=(select auth.uid()) and exists(select 1 from public.earth_teachers t where t.user_id=(select auth.uid())))
 with check(teacher_id=(select auth.uid()) and exists(select 1 from public.earth_teachers t where t.user_id=(select auth.uid())));
revoke all on public.earth_classes from anon,authenticated;
grant select,insert,update on public.earth_classes to authenticated;

create table public.earth_submissions(
 id uuid primary key default gen_random_uuid(),
 class_id uuid not null references public.earth_classes(id) on delete cascade,
 submission_token uuid not null,
 student_name text not null check(length(student_name) between 1 and 20),
 student_number text not null check(length(student_number) between 1 and 10),
 payload jsonb not null check(jsonb_typeof(payload)='object'),
 submitted_at timestamptz not null default now(),
 unique(class_id,submission_token)
);
create index earth_submission_class_time on public.earth_submissions(class_id,submitted_at desc);
alter table public.earth_submissions enable row level security;
create policy teacher_reads_answers on public.earth_submissions for select to authenticated
 using(exists(select 1 from public.earth_classes c where c.id=class_id and c.teacher_id=(select auth.uid())));
revoke all on public.earth_submissions from anon,authenticated;
grant select(id,class_id,student_name,student_number,payload,submitted_at) on public.earth_submissions to authenticated;

create function public.submit_earth_answers(p_code text,p_token uuid,p_name text,p_number text,p_payload jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare target_id uuid; result_time timestamptz;
begin
 if p_token is null or p_name is null or length(trim(p_name)) not between 1 and 20
 or p_number is null or length(trim(p_number)) not between 1 and 10
 or p_payload is null or jsonb_typeof(p_payload)<>'object' or octet_length(p_payload::text)>100000
 or jsonb_typeof(p_payload->'answers') is distinct from 'object'
 or jsonb_typeof(p_payload->'texts') is distinct from 'object' then
 raise exception 'Invalid submission'; end if;
 select id into target_id from public.earth_classes where code=lower(trim(p_code)) and accepting=true for share;
 if target_id is null then raise exception 'Invalid participation code'; end if;
 insert into public.earth_submissions(class_id,submission_token,student_name,student_number,payload)
 values(target_id,p_token,trim(p_name),trim(p_number),p_payload)
 on conflict(class_id,submission_token) do update set student_name=excluded.student_name,
 student_number=excluded.student_number,payload=excluded.payload,submitted_at=now()
 returning submitted_at into result_time;
 return jsonb_build_object('submitted_at',result_time);
end; $$;
revoke all on function public.submit_earth_answers(text,uuid,text,text,jsonb) from public;
grant execute on function public.submit_earth_answers(text,uuid,text,text,jsonb) to anon,authenticated;

-- After creating the teacher in Authentication > Users, run with the real UUID:
-- insert into public.earth_teachers(user_id) values ('TEACHER_AUTH_USER_UUID');
-- Disable public signups in Auth settings. Student anonymous sign-in is NOT needed.

create index earth_classes_teacher_idx on public.earth_classes(teacher_id);

