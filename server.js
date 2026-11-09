const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
require('dotenv').config({ quiet: true });

const appRoutes = require('./routes/app');

require('./models/TournamentGroup');
require('./models/TournamentMatch');
require('./models/TournamentJury');
require('./models/TournamentJuryVote');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  name: 'ata.sid',
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/allthingsaprons' }),
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Facades. The order is part of how the app behaves: the App router starts with a sign-in gate on every
// path, so what logged-out visitors can reach goes before it, and the API sits after it, behind the gate.
const facades = [
  { name: 'Sign-in', mount: '/', router: appRoutes.signIn },
  { name: 'Public', mount: '/', router: require('./routes/public') },
  { name: 'Admin', mount: '/admin', router: require('./routes/admin') },
  { name: 'App', mount: '/', router: appRoutes },
  { name: 'API', mount: '/api', router: require('./routes/api') },
];

facades.forEach(({ mount, router }) => app.use(mount, router));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/allthingsaprons';

mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected');
    const agenda                  = require('./services/jobs/agenda');
    const { registerContestJobs } = require('./services/jobs/contestJobs');
    const { startSweeper }        = require('./services/jobs/sweeper');
    const { registerWalletJobs, startWalletJobs } = require('./services/jobs/walletJobs');
    const { registerTournamentJobs } = require('./services/jobs/tournamentJobs');
    registerContestJobs(agenda);
    registerWalletJobs(agenda);
    registerTournamentJobs(agenda);
    await agenda.start();
    await startSweeper(agenda);
    await startWalletJobs(agenda);
    console.log('Background jobs started');

    async function gracefulShutdown(signal) {
      console.log(`${signal} received — stopping background jobs`);
      await agenda.stop();
      process.exit(0);
    }
    process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.once('SIGINT',  () => gracefulShutdown('SIGINT'));
  })
  .catch((err) => console.warn('MongoDB unavailable — running without DB:', err.message));

app.listen(PORT, () => {
  const local = `http://localhost:${PORT}`;
  console.log(`Server running → ${local}`);
  facades.forEach(({ name, mount, router }) => {
    console.log(`[${name}]`);
    (router.routes || []).forEach(({ method, path: p, label }) => {
      const full = (mount === '/' ? '' : mount) + (p === '/' && mount !== '/' ? '' : p);
      console.log(`  ${method.padEnd(6)} ${local}${full || '/'} — ${label}`);
    });
  });
  console.log('');
});
