-- Run this once in Supabase: SQL Editor -> New query -> paste -> Run
create extension if not exists pgcrypto;

create table schools (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  trial_ends_at timestamptz not null,          -- signup + 7 days
  paid_until timestamptz,                      -- set when school pays
  created_at timestamptz default now()
);

create table users (
  id uuid primary key default gen_random_uuid(),
  school_id uuid references schools(id) on delete cascade,  -- null for superadmin
  role text not null check (role in ('superadmin','admin','teacher','student','parent')),
  login_id text not null unique,               -- phone or email
  password_hash text not null,
  name text,
  subject text,                                -- teacher
  class_name text,                             -- teacher's class / student's class
  created_at timestamptz default now()
);

create table students (
  user_id uuid primary key references users(id) on delete cascade,
  school_id uuid not null references schools(id) on delete cascade,
  class_name text not null,
  roll int not null,
  phone text,
  email text,
  unique (school_id, class_name, roll)
);

create table parent_links (
  parent_id uuid references users(id) on delete cascade,
  student_id uuid references students(user_id) on delete cascade,
  primary key (parent_id, student_id)
);

create table attendance (
  student_id uuid references students(user_id) on delete cascade,
  day date not null,
  status text not null check (status in ('present','absent','late')),
  primary key (student_id, day)
);

create table notices (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  audience text not null check (audience in ('students','teachers','parents')),
  class_name text,                             -- null = whole school
  text text not null,
  from_role text,
  created_at timestamptz default now()
);

create table payments (
  id uuid primary key default gen_random_uuid(),
  school_id uuid references schools(id) on delete cascade,
  students_count int not null,
  amount_inr int not null,
  months int not null default 1,
  paid_at timestamptz default now()
);
