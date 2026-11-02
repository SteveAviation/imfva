import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const q = (t, p = []) => (sql.query ? sql.query(t, p) : sql(t, p));
const SECRET = process.env.SESSION_SECRET;
const ADMINS = (process.env.ADMIN_USERNAME || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
const DAY = 864e5;

const sign = (cs, exp) => crypto.createHmac('sha256', SECRET).update(`${cs}.${exp}`).digest('hex');
const makeToken = cs => { const exp = Date.now() + 7 * DAY; return `${cs}.${exp}.${sign(cs, exp)}`; };
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function who(req) {
  const [cs, exp, sig] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  return cs && exp && sig && +exp > Date.now() && same(sig, sign(cs, exp)) ? cs : null;
}
const hashPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); return `${salt}:${crypto.scryptSync(pw, salt, 32).toString('hex')}`; };
const checkPw = (pw, stored) => { const [salt, h] = stored.split(':'); return same(h, crypto.scryptSync(pw, salt, 32).toString('hex')); };
const clean = (s, n) => String(s ?? '').trim().slice(0, n);
const uname = s => clean(s, 20).toLowerCase().replace(/[^a-z0-9_-]/g, '');
const ID = v => (/^\d{1,18}$/.test(String(v)) ? String(v) : null);

const CRUD = {
  aircraft: { cols: { name: 't', airline: 't' }, order: 'name' },
  routes: { cols: { flight: 't', dep: 't', arr: 't', minutes: 'i', descr: 't' }, order: 'flight' },
  multipliers: { cols: { code: 't', factor: 'n', descr: 't' }, order: 'code' },
  ranks: { cols: { name: 't', min_hours: 'i' }, order: 'min_hours' },
  awards: { cols: { name: 't', descr: 't' }, order: 'name' },
  pilot_awards: { cols: { username: 't', award_id: 'i' }, order: 'id desc' },
};
const castv = (t, v) => (t === 'i' ? parseInt(v, 10) || 0 : t === 'n' ? Number(v) || 1 : clean(v, 200));
const STAFF_ACTIONS = ['users', 'user_set', 'pirep_review', 'live_review', 'admin', 'crud_list', 'crud_save', 'crud_del'];
const PILOT_ACTIONS = ['pirep', 'pireps', 'pirep_get', 'comment', 'catalog', 'live_create', 'live_list'];
const PIREP_SQL = `select p.id::text as id, to_char(p.flown,'YYYY-MM-DD') as flown, p.flight, p.dep, p.arr, p.ac, p.minutes, p.fuel, p.mult, p.status, p.username, pl.name, pl.callsign,
  (select count(*)::int from comments c where c.pirep_id = p.id) as comments, (select airline from aircraft where name = p.ac limit 1) as airline
  from pireps p join pilots pl on pl.username = p.username`;

export default async function handler(req, res) {
  const out = (c, b) => res.status(c).json(b);
  const bad = m => out(400, { error: m });
  if (!process.env.DATABASE_URL || !SECRET) return out(500, { error: 'Server is not configured. Set DATABASE_URL and SESSION_SECRET.' });
  const a = req.query.action, b = req.body || {};
  const log = (u, act, d = '') => q('insert into activity (username, action, detail) values ($1,$2,$3)', [u, act, String(d).slice(0, 200)]);
  try {
    if (a === 'stats') {
      const [s] = await q("select (select count(*) from pilots where status = 'active')::int as pilots, count(*)::int as flights, coalesce(sum(credited), 0)::int as minutes from pireps where status = 'approved'");
      return out(200, s);
    }
    if (a === 'register') {
      const cs = uname(b.cs), name = clean(b.name, 40), pw = String(b.pw ?? ''), email = clean(b.email, 80);
      if (cs.length < 3 || !name || pw.length < 6 || !/^\S+@\S+\.\S+$/.test(email)) return bad('Enter your name, email, a username of 3 or more characters and a password of 6 or more characters.');
      const adm = ADMINS.includes(cs);
      const extra = JSON.stringify({ sim: clean(b.sim, 40), ifc: clean(b.ifc, 60), discord: clean(b.discord, 60), exp: clean(b.exp, 300) });
      const r = await q('insert into pilots (username, name, hub, pw, email, role, status, step, extra) values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) on conflict do nothing returning id',
        [cs, name, clean(b.hub, 4).toUpperCase() || 'ZSAM', hashPw(pw), email, adm ? 'admin' : 'pilot', adm ? 'active' : 'applicant', adm ? 4 : 1, extra]);
      if (!r.length) return out(409, { error: 'That username is taken. Choose another.' });
      await q('update pilots set callsign = $2 where id = $1', [r[0].id, 'XM' + (100 + r[0].id)]);
      await log(cs, 'register', adm ? 'admin' : 'application submitted');
      return out(200, { token: makeToken(cs) });
    }
    if (a === 'login') {
      const cs = uname(b.cs);
      const [r] = await q('select pw, role from pilots where username = $1', [cs]);
      if (!r || !checkPw(String(b.pw ?? ''), r.pw)) return out(401, { error: 'Username or password is wrong.' });
      if (ADMINS.includes(cs) && r.role !== 'admin') await q("update pilots set role = 'admin', status = 'active', step = 4 where username = $1", [cs]);
      await log(cs, 'login');
      return out(200, { token: makeToken(cs) });
    }

    const cs = who(req);
    const [u] = cs ? await q('select * from pilots where username = $1', [cs]) : [];
    if (!u) return out(401, { error: 'Please sign in again.' });
    const staff = u.role === 'staff' || u.role === 'admin', admin = u.role === 'admin', active = u.status === 'active';
    if (STAFF_ACTIONS.includes(a) && !staff) return out(403, { error: 'Staff only.' });
    if (PILOT_ACTIONS.includes(a) && !active && !staff) return out(403, { error: 'Your application is still under review.' });

    if (a === 'me') {
      const [s] = await q("select coalesce(sum(credited) filter (where status = 'approved'), 0)::int as minutes, (count(*) filter (where status = 'approved'))::int as flights, (count(*) filter (where status = 'pending'))::int as pending from pireps where username = $1", [cs]);
      const [rk] = await q('select name from ranks where min_hours <= $1 order by min_hours desc limit 1', [Math.floor(s.minutes / 60)]);
      const aw = await q('select a.name from pilot_awards p join awards a on a.id = p.award_id where p.username = $1', [cs]);
      const { pw, ...pilot } = u;
      pilot.joined = new Date(u.joined).toISOString().slice(0, 10);
      return out(200, { pilot, stats: s, rank: rk ? rk.name : 'Cadet', awards: aw.map(x => x.name), discord: u.step >= 4 || active ? process.env.DISCORD_INVITE_URL || '' : '' });
    }
    if (a === 'declare') {
      await q('update pilots set step = 2 where username = $1 and step = 1', [cs]);
      await log(cs, 'declared written test complete');
      return out(200, { ok: true });
    }
    if (a === 'catalog') {
      const [aircraft, routes, multipliers] = await Promise.all([q('select name, airline from aircraft order by name'), q('select * from routes order by flight'), q('select code, descr from multipliers order by code')]);
      return out(200, { aircraft, routes, multipliers });
    }
    if (a === 'pirep') {
      const flight = clean(b.flight, 8).toUpperCase(), dep = clean(b.dep, 4).toUpperCase(), arr = clean(b.arr, 4).toUpperCase();
      const min = Math.round(+b.min), fuel = Math.max(0, Math.round(+b.fuel || 0)), ac = clean(b.ac, 60), code = clean(b.mult, 20), note = clean(b.note, 300);
      if (!/^[A-Z0-9]{2,8}$/.test(flight) || !/^[A-Z]{4}$/.test(dep) || !/^[A-Z]{4}$/.test(arr) || dep === arr || !ac || !(min >= 1 && min <= 1200) || !/^\d{4}-\d{2}-\d{2}$/.test(String(b.date ?? ''))) return bad('Check the flight number, airports, aircraft, date and flight time.');
      let factor = 1;
      if (code) {
        const [m] = await q('select factor from multipliers where lower(code) = lower($1)', [code]);
        if (!m) return bad('Unknown multiplier code.');
        factor = Number(m.factor);
      }
      const [p] = await q('insert into pireps (username, flown, flight, dep, arr, ac, minutes, fuel, mult, credited, note) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id', [cs, b.date, flight, dep, arr, ac, min, fuel, code, Math.round(min * factor), note]);
      if (note) await q('insert into comments (pirep_id, username, body) values ($1,$2,$3)', [p.id, cs, note]);
      await log(cs, 'filed PIREP', `${flight} ${dep}-${arr} ${min} min`);
      return out(200, { id: p.id });
    }
    if (a === 'pireps') {
      if (b.scope === 'pending' && !staff) return out(403, { error: 'Staff only.' });
      const w = b.scope === 'mine' ? 'where p.username = $1' : b.scope === 'pending' ? "where p.status = 'pending'" : '';
      const rows = await q(`${PIREP_SQL} ${w} order by p.id desc limit 100`, b.scope === 'mine' ? [cs] : []);
      return out(200, { rows });
    }
    if (a === 'pirep_get') {
      const id = ID(b.id);
      if (!id) return bad('Invalid PIREP.');
      const [p] = await q(`${PIREP_SQL} where p.id = $1::bigint`, [id]);
      if (!p) return out(404, { error: 'PIREP not found.' });
      const c = await q("select pl.name, pl.callsign, c.body, to_char(c.at, 'YYYY-MM-DD HH24:MI') as at from comments c join pilots pl on pl.username = c.username where c.pirep_id = $1::bigint order by c.id", [id]);
      return out(200, { p, c });
    }
    if (a === 'comment') {
      const id = ID(b.id), body = clean(b.body, 300);
      if (!id || !body) return bad('Write a comment first.');
      const [n] = await q('select count(*)::int as n from comments where pirep_id = $1::bigint', [id]);
      if (n.n >= 10) return bad('This PIREP has reached the 10 comment limit.');
      await q('insert into comments (pirep_id, username, body) values ($1::bigint,$2,$3)', [id, cs, body]);
      await log(cs, 'commented', `PIREP #${id}`);
      return out(200, { ok: true });
    }
    if (a === 'pirep_review') {
      const id = ID(b.id);
      if (!id || !['approved', 'rejected'].includes(b.status)) return bad('Invalid review.');
      await q('update pireps set status = $2, reviewer = $3 where id = $1::bigint', [id, b.status, cs]);
      await log(cs, `${b.status} PIREP`, `#${id}`);
      return out(200, { ok: true });
    }
    if (a === 'live_create') {
      const f = k => clean(b[k], 60);
      const flight = f('flight').toUpperCase(), dep = f('dep').toUpperCase(), arr = f('arr').toUpperCase();
      if (!/^[A-Z0-9]{2,8}$/.test(flight) || !/^[A-Z]{4}$/.test(dep) || !/^[A-Z]{4}$/.test(arr) || !f('ac') || !f('reg') || !f('sched')) return bad('Fill in the flight number, airports, aircraft, registration and time.');
      const url = /^https?:\/\//.test(clean(b.url, 200)) ? clean(b.url, 200) : '';
      await q('insert into live (username, flight, dep, arr, ac, reg, sched, platform, url, note) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [cs, flight, dep, arr, f('ac'), f('reg').toUpperCase(), f('sched'), f('platform'), url, clean(b.note, 300)]);
      await log(cs, 'requested live slot', `${flight} ${f('reg')}`);
      return out(200, { ok: true });
    }
    if (a === 'live_list') {
      const all = staff && b.all;
      const rows = await q(`select l.id, l.flight, l.dep, l.arr, l.ac, l.reg, l.sched, l.platform, l.url, l.note, l.status, pl.name from live l join pilots pl on pl.username = l.username ${all ? '' : 'where l.username = $1'} order by l.id desc limit 100`, all ? [] : [cs]);
      return out(200, { rows });
    }
    if (a === 'live_review') {
      const id = ID(b.id);
      if (!id || !['approved', 'rejected'].includes(b.status)) return bad('Invalid review.');
      await q('update live set status = $2 where id = $1::int', [id, b.status]);
      await log(cs, `${b.status} live request`, `#${id}`);
      return out(200, { ok: true });
    }
    if (a === 'users') {
      const rows = await q("select username, name, email, hub, role, status, step, score, callsign, extra from pilots order by id desc limit 300");
      return out(200, { rows });
    }
    if (a === 'user_set') {
      const target = uname(b.username);
      const role = admin && ['pilot', 'staff', 'admin'].includes(b.role) ? b.role : null;
      const status = ['applicant', 'active', 'suspended'].includes(b.status) ? b.status : null;
      const score = b.score === '' || b.score == null ? null : Math.max(0, Math.min(100, parseInt(b.score, 10) || 0));
      const step = status === 'active' ? 4 : score != null ? 3 : null;
      await q('update pilots set status = coalesce($2, status), step = greatest(step, coalesce($3::int, step)), score = coalesce($4::int, score), role = coalesce($5, role) where username = $1', [target, status, step, score, role]);
      await log(cs, 'updated user', `${target} ${[status, score != null ? 'score ' + score : '', role].filter(Boolean).join(' ')}`);
      return out(200, { ok: true });
    }
    if (a === 'admin') {
      const [c] = await q("select (select count(*) from pilots where status = 'active')::int as pilots, (select count(*) from pilots where status = 'applicant')::int as applicants, (select count(*) from pireps where status = 'pending')::int as pireps, (select count(*) from live where status = 'pending')::int as live");
      const act = await q("select username, action, detail, to_char(at, 'MM-DD HH24:MI') as at from activity order by id desc limit 40");
      return out(200, { c, act });
    }
    if (a.startsWith('crud_')) {
      const t = CRUD[b.t];
      if (!t) return bad('Unknown table.');
      const names = Object.keys(t.cols);
      if (a === 'crud_list') return out(200, { rows: await q(`select * from ${b.t} order by ${t.order} limit 500`) });
      if (a === 'crud_del') {
        const id = ID(b.id);
        if (!id) return bad('Invalid id.');
        await q(`delete from ${b.t} where id = $1::int`, [id]);
        await log(cs, 'deleted', `${b.t} #${id}`);
        return out(200, { ok: true });
      }
      if (a === 'crud_save') {
        const vals = names.map(k => castv(t.cols[k], b.row?.[k]));
        if (!vals[0]) return bad('Fill in the first field.');
        await q(`insert into ${b.t} (${names.join(',')}) values (${names.map((_, i) => '$' + (i + 1)).join(',')})`, vals);
        await log(cs, 'added', `${b.t}: ${vals[0]}`);
        return out(200, { ok: true });
      }
    }
    return out(404, { error: 'Not found.' });
  } catch (e) {
    console.error(e);
    if (e.code === '23505') return out(409, { error: 'That entry already exists.' });
    return out(500, { error: 'Server error. Try again in a moment.' });
  }
}
