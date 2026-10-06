-- Benedict Books — online bookshop schema (shared Supabase project uwxnbaicwfbygvkiyhcf)
-- RPC-only: anon has no direct table access; everything goes through SECURITY DEFINER functions.

create table if not exists bb_books (
  id bigint generated always as identity primary key,
  title text not null,
  author text not null default '',
  category text not null default 'General',
  isbn text not null default '',
  description text not null default '',
  price numeric(10,2) not null default 0 check (price >= 0),
  stock int not null default 0 check (stock >= 0),
  cover text not null default '',
  featured boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists bb_orders (
  id bigint generated always as identity primary key,
  ref text not null unique,
  customer_name text not null,
  phone text not null,
  email text not null default '',
  address text not null default '',
  delivery text not null default 'collect' check (delivery in ('collect','delivery')),
  items jsonb not null,
  subtotal numeric(10,2) not null,
  delivery_fee numeric(10,2) not null default 0,
  total numeric(10,2) not null,
  notes text not null default '',
  status text not null default 'pending' check (status in ('pending','paid','ready','shipped','completed','cancelled')),
  created_at timestamptz not null default now()
);

create table if not exists bb_settings (
  key text primary key,
  value text not null default ''
);

create table if not exists bb_admins (
  id bigint generated always as identity primary key,
  username text not null unique,
  pass_hash text not null,
  session_token text,
  session_expires timestamptz
);

alter table bb_books enable row level security;
alter table bb_orders enable row level security;
alter table bb_settings enable row level security;
alter table bb_admins enable row level security;
revoke all on bb_books, bb_orders, bb_settings, bb_admins from anon, authenticated;

-- ---------- helpers ----------
create or replace function bb_check_admin(p_token text) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare v_id bigint;
begin
  select id into v_id from bb_admins
   where session_token = p_token and session_expires > now();
  if v_id is null then raise exception 'Session expired. Please sign in again.'; end if;
  return v_id;
end $$;
revoke all on function bb_check_admin(text) from public, anon, authenticated;

-- ---------- public ----------
create or replace function bb_list_books() returns setof bb_books
language sql stable security definer set search_path = public, extensions as $$
  select * from bb_books where active order by featured desc, created_at desc;
$$;

create or replace function bb_get_settings() returns jsonb
language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) from bb_settings;
$$;

create or replace function bb_place_order(
  p_name text, p_phone text, p_email text, p_address text,
  p_delivery text, p_items jsonb, p_notes text
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  it jsonb; b bb_books; v_qty int;
  v_lines jsonb := '[]'::jsonb; v_sub numeric := 0; v_fee numeric := 0;
  v_ref text; v_alpha text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
begin
  if coalesce(trim(p_name),'') = '' or coalesce(trim(p_phone),'') = '' then
    raise exception 'Name and phone number are required.'; end if;
  if p_delivery not in ('collect','delivery') then raise exception 'Invalid delivery option.'; end if;
  if p_delivery = 'delivery' and coalesce(trim(p_address),'') = '' then
    raise exception 'A delivery address is required.'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 then
    raise exception 'Your cart is empty.'; end if;

  for it in select * from jsonb_array_elements(p_items) loop
    v_qty := (it->>'qty')::int;
    if v_qty is null or v_qty < 1 or v_qty > 50 then raise exception 'Invalid quantity.'; end if;
    select * into b from bb_books where id = (it->>'id')::bigint and active for update;
    if not found then raise exception 'A book in your cart is no longer available.'; end if;
    if b.stock < v_qty then
      raise exception '"%" only has % left in stock.', b.title, b.stock; end if;
    update bb_books set stock = stock - v_qty where id = b.id;
    v_lines := v_lines || jsonb_build_object('id', b.id, 'title', b.title, 'author', b.author,
                                             'price', b.price, 'qty', v_qty);
    v_sub := v_sub + b.price * v_qty;
  end loop;

  if p_delivery = 'delivery' then
    select coalesce(nullif(value,'')::numeric, 0) into v_fee from bb_settings where key = 'delivery_fee';
    v_fee := coalesce(v_fee, 0);
  end if;

  loop
    v_ref := 'BB-' || (select string_agg(substr(v_alpha, 1 + (get_byte(gen_random_bytes(1),0) % length(v_alpha)), 1), '')
                       from generate_series(1,6));
    exit when not exists (select 1 from bb_orders where ref = v_ref);
  end loop;

  insert into bb_orders(ref, customer_name, phone, email, address, delivery, items, subtotal, delivery_fee, total, notes)
  values (v_ref, left(trim(p_name),120), left(trim(p_phone),30), left(trim(coalesce(p_email,'')),120),
          left(trim(coalesce(p_address,'')),500), p_delivery, v_lines, v_sub, v_fee, v_sub + v_fee,
          left(trim(coalesce(p_notes,'')),1000));

  return jsonb_build_object('ref', v_ref, 'items', v_lines, 'subtotal', v_sub, 'delivery_fee', v_fee, 'total', v_sub + v_fee);
end $$;

create or replace function bb_track_order(p_ref text, p_phone text) returns jsonb
language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('ref', ref, 'status', status, 'total', total, 'items', items,
                            'delivery', delivery, 'created_at', created_at)
    from bb_orders
   where ref = upper(trim(p_ref))
     and regexp_replace(phone, '\D', '', 'g') = regexp_replace(p_phone, '\D', '', 'g');
$$;

-- ---------- admin ----------
create or replace function bb_admin_login(p_username text, p_password text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare a bb_admins; v_tok text;
begin
  select * into a from bb_admins where lower(username) = lower(trim(p_username));
  if not found or a.pass_hash <> crypt(p_password, a.pass_hash) then
    perform pg_sleep(0.5);
    raise exception 'Incorrect username or password.';
  end if;
  v_tok := encode(gen_random_bytes(32), 'hex');
  update bb_admins set session_token = v_tok, session_expires = now() + interval '12 hours' where id = a.id;
  return v_tok;
end $$;

create or replace function bb_admin_logout(p_token text) returns void
language sql security definer set search_path = public, extensions as $$
  update bb_admins set session_token = null, session_expires = null where session_token = p_token;
$$;

create or replace function bb_admin_change_password(p_token text, p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_id bigint := bb_check_admin(p_token); a bb_admins;
begin
  select * into a from bb_admins where id = v_id;
  if a.pass_hash <> crypt(p_old, a.pass_hash) then raise exception 'Current password is incorrect.'; end if;
  if length(coalesce(p_new,'')) < 8 then raise exception 'New password must be at least 8 characters.'; end if;
  update bb_admins set pass_hash = crypt(p_new, gen_salt('bf')) where id = v_id;
end $$;

create or replace function bb_admin_books(p_token text) returns setof bb_books
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  perform bb_check_admin(p_token);
  return query select * from bb_books order by created_at desc;
end $$;

create or replace function bb_admin_save_book(p_token text, p_book jsonb) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare v_id bigint;
begin
  perform bb_check_admin(p_token);
  if coalesce(trim(p_book->>'title'),'') = '' then raise exception 'Title is required.'; end if;
  if (p_book->>'id') is null or (p_book->>'id') = '' then
    insert into bb_books(title, author, category, isbn, description, price, stock, cover, featured, active)
    values (trim(p_book->>'title'), coalesce(p_book->>'author',''), coalesce(nullif(trim(p_book->>'category'),''),'General'),
            coalesce(p_book->>'isbn',''), coalesce(p_book->>'description',''),
            coalesce((p_book->>'price')::numeric,0), coalesce((p_book->>'stock')::int,0),
            coalesce(p_book->>'cover',''), coalesce((p_book->>'featured')::boolean,false),
            coalesce((p_book->>'active')::boolean,true))
    returning id into v_id;
  else
    v_id := (p_book->>'id')::bigint;
    update bb_books set
      title = trim(p_book->>'title'), author = coalesce(p_book->>'author',''),
      category = coalesce(nullif(trim(p_book->>'category'),''),'General'),
      isbn = coalesce(p_book->>'isbn',''), description = coalesce(p_book->>'description',''),
      price = coalesce((p_book->>'price')::numeric,0), stock = coalesce((p_book->>'stock')::int,0),
      cover = coalesce(p_book->>'cover',''), featured = coalesce((p_book->>'featured')::boolean,false),
      active = coalesce((p_book->>'active')::boolean,true)
    where id = v_id;
    if not found then raise exception 'Book not found.'; end if;
  end if;
  return v_id;
end $$;

create or replace function bb_admin_delete_book(p_token text, p_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform bb_check_admin(p_token);
  delete from bb_books where id = p_id;
end $$;

create or replace function bb_admin_orders(p_token text) returns setof bb_orders
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  perform bb_check_admin(p_token);
  return query select * from bb_orders order by created_at desc limit 1000;
end $$;

create or replace function bb_admin_set_order_status(p_token text, p_ref text, p_status text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare o bb_orders; it jsonb;
begin
  perform bb_check_admin(p_token);
  select * into o from bb_orders where ref = p_ref for update;
  if not found then raise exception 'Order not found.'; end if;
  if p_status not in ('pending','paid','ready','shipped','completed','cancelled') then
    raise exception 'Invalid status.'; end if;
  -- restock when cancelling; take stock again when un-cancelling
  if p_status = 'cancelled' and o.status <> 'cancelled' then
    for it in select * from jsonb_array_elements(o.items) loop
      update bb_books set stock = stock + (it->>'qty')::int where id = (it->>'id')::bigint;
    end loop;
  elsif p_status <> 'cancelled' and o.status = 'cancelled' then
    for it in select * from jsonb_array_elements(o.items) loop
      update bb_books set stock = greatest(stock - (it->>'qty')::int, 0) where id = (it->>'id')::bigint;
    end loop;
  end if;
  update bb_orders set status = p_status where id = o.id;
end $$;

create or replace function bb_admin_delete_order(p_token text, p_ref text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform bb_check_admin(p_token);
  delete from bb_orders where ref = p_ref;
end $$;

create or replace function bb_admin_save_settings(p_token text, p_settings jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare k text; v text;
begin
  perform bb_check_admin(p_token);
  for k, v in select * from jsonb_each_text(p_settings) loop
    if k in ('shop_name','tagline','whatsapp','email','bank_name','account_name','account_number',
             'branch_code','delivery_fee','delivery_note','collect_note','about') then
      insert into bb_settings(key, value) values (k, left(coalesce(v,''), 2000))
      on conflict (key) do update set value = excluded.value;
    end if;
  end loop;
end $$;

-- grants: public RPCs + admin RPCs (which self-check the session token)
revoke all on function bb_list_books(), bb_get_settings(), bb_place_order(text,text,text,text,text,jsonb,text),
  bb_track_order(text,text), bb_admin_login(text,text), bb_admin_logout(text),
  bb_admin_change_password(text,text,text), bb_admin_books(text), bb_admin_save_book(text,jsonb),
  bb_admin_delete_book(text,bigint), bb_admin_orders(text), bb_admin_set_order_status(text,text,text),
  bb_admin_delete_order(text,text), bb_admin_save_settings(text,jsonb) from public;
grant execute on function bb_list_books(), bb_get_settings(), bb_place_order(text,text,text,text,text,jsonb,text),
  bb_track_order(text,text), bb_admin_login(text,text), bb_admin_logout(text),
  bb_admin_change_password(text,text,text), bb_admin_books(text), bb_admin_save_book(text,jsonb),
  bb_admin_delete_book(text,bigint), bb_admin_orders(text), bb_admin_set_order_status(text,text,text),
  bb_admin_delete_order(text,text), bb_admin_save_settings(text,jsonb) to anon, authenticated;

-- ---------- bootstrap ----------
insert into bb_admins(username, pass_hash)
values ('benedict', extensions.crypt('ChangeMe123!', extensions.gen_salt('bf')))
on conflict (username) do nothing;

insert into bb_settings(key, value) values
  ('shop_name', 'Benedict Books'),
  ('tagline', 'Good books, delivered to your door.'),
  ('whatsapp', ''),
  ('email', ''),
  ('bank_name', ''), ('account_name', 'Benedict Mohlatswa'), ('account_number', ''), ('branch_code', ''),
  ('delivery_fee', '100'),
  ('delivery_note', 'Delivery via courier, 2–5 working days.'),
  ('collect_note', 'Collect by arrangement — we will WhatsApp you when your order is ready.'),
  ('about', 'An independent bookshop run by Benedict Mohlatswa. New and pre-loved books across fiction, faith, business, self-development, children''s books and more.')
on conflict (key) do nothing;
