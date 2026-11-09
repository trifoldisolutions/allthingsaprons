const express = require('express');
const injectNotificationCount = require('../middleware/injectNotificationCount');
const injectRightPanelData    = require('../middleware/injectRightPanelData');

// Each function below holds one part of this section, with its own router and its own scope, so names
// can repeat between parts and a part's middleware stays on its own routes. The code inside isn't
// indented, so multi-line strings stay as they were.

// ── Sign-up, log-in and log-out ───────────────────────────────────────────
function authRoutes() {
const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const { Resend } = require('resend');
const User        = require('../models/User');
const BannedEmail = require('../models/BannedEmail');
const upload   = require('../middleware/upload');

const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@allthingsaprons.com';

function getResend() {
  if (!process.env.RESEND_API_KEY) return null;
  return new Resend(process.env.RESEND_API_KEY);
}

function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── Signup ────────────────────────────────────────────────────────

router.get('/signup', (req, res) => {
  if (req.session.userId) return res.redirect('/feed');
  res.render('app/auth/signup', { title: 'Sign Up', error: null, editUser: null });
});

router.post('/auth/send-otp', async (req, res) => {
  const { email, username } = req.body;
  try {
    if (!req.session.userId) {
      const [existing, banned] = await Promise.all([
        User.findOne({ $or: [{ 'email.value': email.toLowerCase() }, { 'username.value': username.toLowerCase() }] }),
        BannedEmail.exists({ email: email.toLowerCase() }),
      ]);
      if (banned) {
        return res.json({ ok: false, field: 'email', message: 'Email already registered.' });
      }
      if (existing) {
        if (existing.email.value === email.toLowerCase()) {
          return res.json({ ok: false, field: 'email', message: 'Email already registered.' });
        }
        return res.json({ ok: false, field: 'username', message: 'Username already taken.' });
      }
    }

    const code = genOtp();
    req.session.pendingOtp = { email: email.toLowerCase(), code };

    const resend = getResend();
    if (resend) {
      await resend.emails.send({
        from: FROM_EMAIL,
        to: email,
        subject: 'Your AllThingsAprons verification code',
        html: `<p style="font-family:sans-serif">Your verification code is: <strong style="font-size:24px;letter-spacing:4px">${code}</strong></p><p style="font-family:sans-serif;color:#666">This code does not expire.</p>`,
      });
      res.json({ ok: true });
    } else {
      console.log(`[DEV OTP] ${email} → ${code}`);
      res.json({ ok: true, devCode: code });
    }
  } catch (err) {
    console.error('send-otp error:', err);
    res.json({ ok: false, message: 'Failed to send code. Please try again.' });
  }
});

router.post('/signup', upload.avatar.fields([{ name: 'avatar', maxCount: 1 }]), async (req, res) => {
  const renderError = (msg) => res.render('app/auth/signup', { title: 'Sign Up', error: msg, editUser: null });

  try {
    const {
      username, displayName, email, password, confirmPassword,
      bio, sex, orientation, location, birthdate, otp,
      ageAcknowledged, adultContentAcknowledged,
    } = req.body;

    const pending = req.session.pendingOtp;
    if (!pending || pending.email !== email.toLowerCase() || pending.code !== String(otp).trim()) {
      return renderError('Invalid or expired verification code. Please go back and try again.');
    }

    if (!username || !displayName || !email || !sex || !birthdate) {
      return renderError('Please complete all required fields.');
    }
    if (!/^[a-zA-Z][a-zA-Z0-9]{2,14}$/.test(username)) {
      return renderError('Username must start with a letter, contain only letters and digits, and be 3–15 characters.');
    }
    const displayNameTrimmed = displayName.trim();
    const displayNameWords   = displayNameTrimmed.split(/\s+/).filter(Boolean).length;
    if (!displayNameTrimmed) return renderError('Display name is required.');
    if (displayNameWords > 3) return renderError('Display name can be at most 3 words.');
    if (displayNameTrimmed.length > 50) return renderError('Display name cannot exceed 50 characters.');
    const bioCharCount = bio ? bio.replace(/\s/g, '').length : 0;
    if (bioCharCount > 0 && (bioCharCount < 20 || bioCharCount > 220)) {
      return renderError('Bio must be between 20 and 220 characters (spaces not counted).');
    }

    // ── New signup path ──────────────────────────────────────────────
    if (!password) return renderError('Please complete all required fields.');
    if (password !== confirmPassword) return renderError('Passwords do not match.');
    const pwLower   = (password.match(/[a-z]/g) || []).length;
    const pwUpper   = (password.match(/[A-Z]/g) || []).length;
    const pwDigit   = (password.match(/[0-9]/g) || []).length;
    const pwSpecial = (password.match(/[^a-zA-Z0-9]/g) || []).length;
    if (password.length < 12 || pwLower < 3 || pwUpper < 3 || pwDigit < 3 || pwSpecial < 3) {
      return renderError('Password must be at least 12 characters with 3+ lowercase, 3+ uppercase, 3+ digits, and 3+ special characters.');
    }

    if (ageAcknowledged !== 'on') return renderError('You must confirm that you are 18 years of age or older.');
    if (adultContentAcknowledged !== 'on') return renderError('You must acknowledge that this platform contains adult-rated content.');

    const [existing, banned] = await Promise.all([
      User.findOne({ $or: [{ 'email.value': email.toLowerCase() }, { 'username.value': username.toLowerCase() }] }),
      BannedEmail.exists({ email: email.toLowerCase() }),
    ]);
    if (banned) return renderError('This email is already registered.');
    if (existing) {
      if (existing.email.value === email.toLowerCase()) {
        return renderError('This email is already registered.');
      }
      return renderError('This username is already taken.');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const avatarPath     = req.files?.avatar?.[0]
      ? `/uploads/avatars/${req.files.avatar[0].filename}`
      : null;

    const now = new Date();

    const createData = {
      password: hashedPassword,
      email: {
        value:     email.toLowerCase().trim(),
        confirmed: true,
        history:   [{ value: email.toLowerCase().trim(), setAt: now, source: 'signup' }],
      },
      username: {
        value:   username.toLowerCase().trim(),
        history: [{ value: username.toLowerCase().trim(), setAt: now, source: 'signup' }],
      },
      displayName: {
        value:   displayNameTrimmed,
        history: [{ value: displayNameTrimmed, setAt: now, source: 'signup' }],
      },
      sex: {
        value:   sex,
        history: [{ value: sex, setAt: now, source: 'signup' }],
      },
      birthdate: {
        value:   new Date(birthdate),
        history: [{ value: new Date(birthdate), setAt: now, source: 'signup' }],
      },
      ageAcknowledged:            true,
      ageAcknowledgedAt:          now,
      adultContentAcknowledged:   true,
      adultContentAcknowledgedAt: now,
      accountStatus:              'active',
    };

    if (bio) {
      createData.bio = { value: bio.trim(), history: [{ value: bio.trim(), setAt: now, source: 'signup' }] };
    }
    if (orientation) {
      createData.orientation = { value: orientation, history: [{ value: orientation, setAt: now, source: 'signup' }] };
    }
    if (location) {
      createData.location = { value: location, history: [{ value: location, setAt: now, source: 'signup' }] };
    }
    if (avatarPath) {
      createData.avatar = { value: avatarPath, history: [{ value: avatarPath, setAt: now, source: 'signup' }] };
    }

    const user = await User.create(createData);

    delete req.session.pendingOtp;
    req.session.userId = user._id.toString();
    res.redirect('/feed');
  } catch (err) {
    console.error('Signup error:', err);
    renderError('Something went wrong. Please try again.');
  }
});

// ── Login ─────────────────────────────────────────────────────────

router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/feed');
  res.render('app/auth/login', { title: 'Log In', error: null });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ 'email.value': email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('app/auth/login', { title: 'Log In', error: 'Invalid email or password.' });
    }
    req.session.userId = user._id.toString();
    res.redirect('/feed');
  } catch (err) {
    console.error('Login error:', err);
    res.render('app/auth/login', { title: 'Log In', error: 'Something went wrong. Please try again.' });
  }
});

// ── Logout ────────────────────────────────────────────────────────

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

return router;
}

// ── Identity check ────────────────────────────────────────────────────────
function verifyIdentityRoutes() {
const express   = require('express');
const router    = express.Router();
const fs        = require('fs');
const crypto    = require('crypto');
const User      = require('../models/User');
const BannedDocHash         = require('../models/BannedDocHash');
const requireAuth           = require('../middleware/requireAuth');
const upload                = require('../middleware/upload');
const logAuditEvent         = require('../services/auditLog');
const { generateCaseRef }   = require('../services/auditLog');

router.use(requireAuth);

function genVerificationCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// GET /verify-identity
router.get('/', async (req, res) => {
  const user = await User.findById(req.session.userId)
    .select('idVerified idVerificationStatus idVerifyBlockedUntil idVerificationRejectionReasons idVerificationClaimNumber');
  if (!user) { req.session.destroy(() => {}); return res.redirect('/signup'); }

  if (user.idVerified) return res.redirect('/feed');

  const now     = new Date();
  const blocked = !!(user.idVerifyBlockedUntil && user.idVerifyBlockedUntil > now);
  const pending = !blocked && user.idVerificationStatus === 'pending';
  const showRejection = !pending && !blocked && user.idVerificationRejectionReasons?.length;

  res.render('app/verify-identity', {
    title:            'Verify Identity',
    blocked,
    blockedUntil:     blocked ? user.idVerifyBlockedUntil : null,
    pending,
    activeCode:       req.session.verificationCode   || null,
    codeGeneratedAt:  req.session.verificationCodeAt || null,
    error:            req.query.error || null,
    reason:           req.query.reason || null,
    rejectionReasons: showRejection ? user.idVerificationRejectionReasons : [],
    claimNumber:      showRejection ? (user.idVerificationClaimNumber || null) : null,
  });
});

// GET /verify-identity/code — generate selfie code
router.get('/code', async (req, res) => {
  const user = await User.findById(req.session.userId)
    .select('idVerified idVerifyBlockedUntil');
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });
  if (user.idVerified) return res.status(403).json({ error: 'Already verified.' });

  if (user.idVerifyBlockedUntil && user.idVerifyBlockedUntil > new Date()) {
    return res.status(429).json({ error: 'Account temporarily blocked.', blockedUntil: user.idVerifyBlockedUntil });
  }

  const code = genVerificationCode();
  req.session.verificationCode   = code;
  req.session.verificationCodeAt = Date.now();
  res.json({ code });
});

// POST /verify-identity — submit docs for review
router.post('/', upload.idDocs.fields([{ name: 'idSelfie', maxCount: 1 }, { name: 'idDoc', maxCount: 1 }]), async (req, res) => {
  const selfie = req.files?.idSelfie?.[0];
  const idDoc  = req.files?.idDoc?.[0];
  const code   = req.session.verificationCode;

  const fail = (msg) => res.redirect(`/verify-identity?error=${encodeURIComponent(msg)}`);

  if (!selfie) return fail('Please upload your verification selfie.');
  if (!idDoc)  return fail('Please upload a photo of your ID.');
  if (!code)   return fail('No active verification code found. Please generate a code and try again.');

  const submitter = await User.findById(req.session.userId)
    .select('idVerifyBlockedUntil idVerificationStatus idVerifyFailedAttempts idVerificationCaseRef');

  if (!submitter) return fail('Session expired. Please log in again.');

  if (submitter.idVerificationStatus === 'closed') {
    return fail('Your identity verification case has been permanently closed. Please contact support.');
  }

  if (submitter.idVerifyFailedAttempts >= 5) {
    return fail('Your identity verification case has been permanently closed. Please contact support.');
  }

  if (submitter.idVerifyBlockedUntil && submitter.idVerifyBlockedUntil > new Date()) {
    return fail('Your account is temporarily blocked from re-submitting. Please wait for the cooldown to expire.');
  }

  const docBytes = fs.readFileSync(idDoc.path);
  const docHash  = crypto.createHash('sha256').update(docBytes).digest('hex');

  const isBannedDoc = await BannedDocHash.exists({ hash: docHash });
  if (isBannedDoc) {
    fs.unlink(selfie.path, () => {});
    fs.unlink(idDoc.path,  () => {});
    return fail('This document has been flagged and cannot be used for verification. Please contact support.');
  }

  const conflictingUser = await User.findOne({
    idDocHash: docHash,
    _id: { $ne: req.session.userId },
  }).select('_id').lean();

  const caseRef     = submitter.idVerificationCaseRef || generateCaseRef();
  const submittedAt = new Date();
  const attemptNum  = (submitter.idVerifyFailedAttempts || 0) + 1;

  await User.findByIdAndUpdate(req.session.userId, {
    idVerificationStatus:      'pending',
    idSelfieUrl:               `/uploads/id-docs/${selfie.filename}`,
    idDocUrl:                  `/uploads/id-docs/${idDoc.filename}`,
    idVerificationCode:        code,
    idVerificationSubmittedAt: submittedAt,
    idVerificationCaseRef:     caseRef,
    idDocHash:                 docHash,
    $unset: { idVerificationRejectionReasons: '' },
  });

  logAuditEvent({
    actorId:    req.session.userId,
    actorRole:  'user',
    action:     'id_verification_submitted',
    entityType: 'user',
    entityId:   req.session.userId,
    caseRef,
    metadata:   {
      submittedAt,
      attempt:           attemptNum,
      docHashConflict:   !!conflictingUser,
      conflictingUserId: conflictingUser?._id || null,
    },
  });

  delete req.session.verificationCode;

  res.redirect('/verify-identity');
});

return router;
}

// ── Support threads ───────────────────────────────────────────────────────
function contactRoutes() {
const express            = require('express');
const router             = express.Router();
const User               = require('../models/User');
const SupportThread      = require('../models/SupportThread');
const SupportMessage     = require('../models/SupportMessage');
const WalletTransaction  = require('../models/WalletTransaction');
const requireAuth        = require('../middleware/requireAuth');
const upload             = require('../middleware/upload');

const { TOPIC_LABELS } = SupportThread;

router.use(requireAuth);

// GET /contact — thread list
router.get('/', async (req, res) => {
  try {
    const threads = await SupportThread.find({ userId: req.session.userId })
      .sort({ updatedAt: -1 })
      .lean();

    const threadIds = threads.map(t => t._id);

    const [lastMessages, unreadCounts] = await Promise.all([
      SupportMessage.aggregate([
        { $match: { threadId: { $in: threadIds } } },
        { $sort: { createdAt: -1 } },
        { $group: { _id: '$threadId', lastMessage: { $first: '$$ROOT' } } },
      ]),
      SupportMessage.aggregate([
        { $match: { threadId: { $in: threadIds }, from: 'support', readByUser: false } },
        { $group: { _id: '$threadId', count: { $sum: 1 } } },
      ]),
    ]);

    const lastMsgMap = {};
    lastMessages.forEach(m => { lastMsgMap[String(m._id)] = m.lastMessage; });
    const unreadMap = {};
    unreadCounts.forEach(u => { unreadMap[String(u._id)] = u.count; });

    const enriched = threads.map(t => ({
      ...t,
      label:       TOPIC_LABELS[t.topic] || t.topic,
      lastMessage: lastMsgMap[String(t._id)] || null,
      unreadCount: unreadMap[String(t._id)] || 0,
    }));

    res.render('app/contact', { title: 'Support', threads: enriched, TOPIC_LABELS });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading threads');
  }
});

// GET /contact/new?topic=X&txId=Y — find or create open thread, redirect into it
router.get('/new', async (req, res) => {
  try {
    const validTopics = SupportThread.schema.path('topic').enumValues;
    const topic = validTopics.includes(req.query.topic) ? req.query.topic : 'general';
    const txId  = req.query.txId || null;
    const contentType = req.query.contentType || null;

    let thread = await SupportThread.findOne({
      userId: req.session.userId,
      topic,
      status: 'open',
    });

    const isNew = !thread;
    if (!thread) {
      thread = await SupportThread.create({ userId: req.session.userId, topic });
    }

    // Auto-post a reference message for moderation disputes
    if (isNew && topic === 'moderation') {
      const label = contentType === 'entry' ? 'entry' : contentType === 'comment' ? 'comment' : 'content';
      const body  = `I'd like to dispute a moderation decision.\n\nThe ${label} was removed and I believe it did not violate the community guidelines. Please review this decision.`;
      await SupportMessage.create({
        threadId:      thread._id,
        userId:        req.session.userId,
        from:          'user',
        body,
        readBySupport: false,
        readByUser:    true,
      });
      await SupportThread.findByIdAndUpdate(thread._id, { updatedAt: new Date() });
    }

    // Auto-post a reference message when opening a billing dispute from a transaction page
    if (isNew && topic === 'billing' && txId) {
      const tx = await WalletTransaction.findOne({ _id: txId, userId: req.session.userId }).lean();
      if (tx) {
        const txLabels = {
          top_up:                  'Top Up',
          contribution:            'Contribution',
          contribution_adjustment: 'Contribution Adjusted',
          contribution_withdrawal: 'Contribution Withdrawn',
          contest_payout_settled:  'Contest Payout',
          auto_payout:             'Auto-Payout',
          makeup_payout:           'Makeup Payout',
          admin_grant:             'Admin Grant',
          platform_fee:            'Platform Fee',
          manual_correction:       'Manual Correction',
        };
        const label  = txLabels[tx.type] || tx.type;
        const sign   = tx.direction === 'credit' ? '+' : '−';
        const date   = new Date(tx.createdAt).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
        const body   = `I'd like to dispute a transaction.\n\nType: ${label}\nAmount: ${sign}${tx.amountCHL.toLocaleString()} 🌶️ ($${tx.amountUSD.toFixed(2)})\nDate: ${date}\nTransaction ID: ${tx._id}`;
        await SupportMessage.create({
          threadId:      thread._id,
          userId:        req.session.userId,
          from:          'user',
          body,
          readBySupport: false,
          readByUser:    true,
        });
        await SupportThread.findByIdAndUpdate(thread._id, { updatedAt: new Date() });
      }
    }

    res.redirect('/contact/thread/' + thread._id);
  } catch (err) {
    console.error(err);
    res.redirect('/contact');
  }
});

// GET /contact/thread/:threadId — render chat view
router.get('/thread/:threadId', async (req, res) => {
  try {
    const [thread, allThreads] = await Promise.all([
      SupportThread.findOne({ _id: req.params.threadId, userId: req.session.userId }).lean(),
      SupportThread.find({ userId: req.session.userId }).sort({ updatedAt: -1 }).lean(),
    ]);

    if (!thread) return res.redirect('/contact');

    const threadIds = allThreads.map(t => t._id);
    const [lastMessages, unreadCounts] = await Promise.all([
      SupportMessage.aggregate([
        { $match: { threadId: { $in: threadIds } } },
        { $sort: { createdAt: -1 } },
        { $group: { _id: '$threadId', lastMessage: { $first: '$$ROOT' } } },
      ]),
      SupportMessage.aggregate([
        { $match: { threadId: { $in: threadIds }, from: 'support', readByUser: false } },
        { $group: { _id: '$threadId', count: { $sum: 1 } } },
      ]),
    ]);

    const lastMsgMap = {};
    lastMessages.forEach(m => { lastMsgMap[String(m._id)] = m.lastMessage; });
    const unreadMap = {};
    unreadCounts.forEach(u => { unreadMap[String(u._id)] = u.count; });

    const threads = allThreads.map(t => ({
      ...t,
      label:       TOPIC_LABELS[t.topic] || t.topic,
      lastMessage: lastMsgMap[String(t._id)] || null,
      unreadCount: unreadMap[String(t._id)] || 0,
    }));

    res.render('app/contact-thread', {
      title:   TOPIC_LABELS[thread.topic] || 'Support',
      thread:  { ...thread, label: TOPIC_LABELS[thread.topic] || thread.topic },
      threads,
    });
  } catch (err) {
    console.error(err);
    res.redirect('/contact');
  }
});

// GET /contact/thread/:threadId/messages — load messages (JSON)
router.get('/thread/:threadId/messages', async (req, res) => {
  try {
    const thread = await SupportThread.findOne({
      _id:    req.params.threadId,
      userId: req.session.userId,
    });
    if (!thread) return res.status(403).json({ error: 'Not found' });

    const messages = await SupportMessage.find({ threadId: thread._id })
      .sort({ createdAt: 1 })
      .lean();

    await SupportMessage.updateMany(
      { threadId: thread._id, from: 'support', readByUser: false },
      { $set: { readByUser: true } }
    );

    res.json({ messages, threadClosed: thread.status === 'closed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});

// POST /contact/thread/:threadId/messages — send message
router.post('/thread/:threadId/messages', upload.support.array('support', 5), async (req, res) => {
  try {
    const thread = await SupportThread.findOne({
      _id:    req.params.threadId,
      userId: req.session.userId,
      status: 'open',
    });
    if (!thread) return res.status(403).json({ error: 'Thread not found or closed' });

    const body        = (req.body.body || '').trim().slice(0, 500);
    const attachments = (req.files || []).map(f => '/uploads/support/' + f.filename);

    if (!body && attachments.length === 0) {
      return res.status(400).json({ error: 'Message cannot be empty' });
    }

    const msg = await SupportMessage.create({
      threadId:      thread._id,
      userId:        req.session.userId,
      from:          'user',
      body,
      attachments,
      readBySupport: false,
      readByUser:    true,
    });

    await SupportThread.findByIdAndUpdate(thread._id, { updatedAt: new Date() });

    res.json({ message: msg });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// GET /contact/unread — total unread count across all user threads (used for toast/badge)
router.get('/unread', async (req, res) => {
  try {
    const threads = await SupportThread.find({ userId: req.session.userId }).select('_id').lean();
    const threadIds = threads.map(t => t._id);

    const count = await SupportMessage.countDocuments({
      threadId:   { $in: threadIds },
      from:       'support',
      readByUser: false,
    });

    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check unread' });
  }
});

return router;
}

// ── Follow and unfollow ───────────────────────────────────────────────────
function followRoutes() {
const express      = require('express');
const router       = express.Router();
const User         = require('../models/User');
const Follow       = require('../models/Follow');
const requireAuth  = require('../middleware/requireAuth');
const requireApproved = require('../middleware/requireApproved');
const { updateCreatorAffinity } = require('../services/affinityUpdater');

router.use(requireAuth);
router.use(requireApproved);

router.post('/follow/:username', async (req, res) => {
  try {
    const target = await User.findOne({ 'username.value': req.params.username.toLowerCase() }).select('_id').lean();
    if (!target) return res.status(404).json({ error: 'User not found' });

    const followerId  = req.session.userId;
    const followingId = target._id.toString();

    if (followerId === followingId) return res.status(400).json({ error: 'Cannot follow yourself' });

    await Follow.updateOne(
      { followerId, followingId },
      { followerId, followingId },
      { upsert: true }
    );

    const followerCount = await Follow.countDocuments({ followingId });
    res.json({ following: true, followerCount });

    updateCreatorAffinity(followerId, followingId, 0.8).catch(() => {});
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/unfollow/:username', async (req, res) => {
  try {
    const target = await User.findOne({ 'username.value': req.params.username.toLowerCase() }).select('_id').lean();
    if (!target) return res.status(404).json({ error: 'User not found' });

    const followerId  = req.session.userId;
    const followingId = target._id.toString();

    await Follow.deleteOne({ followerId, followingId });

    const followerCount = await Follow.countDocuments({ followingId });
    res.json({ following: false, followerCount });

    updateCreatorAffinity(followerId, followingId, 0).catch(() => {});
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

return router;
}

// ── Wallet ────────────────────────────────────────────────────────────────
function walletRoutes() {
const express  = require('express');
const router   = express.Router();
const mongoose = require('mongoose');
const XLSX     = require('xlsx');
const User     = require('../models/User');
const WalletTransaction = require('../models/WalletTransaction');
const ContestPayout     = require('../models/ContestPayout');
const MonthlySnapshot   = require('../models/MonthlySnapshot');
const Notification      = require('../models/Notification');

const EXCHANGE_RATE = 0.20;

const TX_LABELS = {
  top_up:                  'Top Up',
  contribution:            'Contribution',
  contribution_adjustment: 'Contribution Adjusted',
  contribution_withdrawal: 'Contribution Withdrawn',
  contest_payout_settled:  'Contest Payout',
  auto_payout:             'Auto-Payout',
  makeup_payout:           'Makeup Payout',
  admin_grant:             'Admin Grant',
  platform_fee:            'Platform Fee',
  manual_correction:       'Manual Correction',
  tournament_prize_hold:   'Tournament Prize Hold',
  tournament_prize_refund: 'Tournament Prize Refund',
};

function buildTxFilter(userId, month, type, months, types) {
  const filter = { userId };
  const monthList = months
    ? months.split(',').map(m => m.trim()).filter(m => /^\d{4}-\d{2}$/.test(m))
    : (month && /^\d{4}-\d{2}$/.test(month) ? [month] : []);
  if (monthList.length === 1) {
    const [y, m] = monthList[0].split('-').map(Number);
    filter.createdAt = { $gte: new Date(y, m - 1, 1), $lt: new Date(y, m, 1) };
  } else if (monthList.length > 1) {
    filter.$or = monthList.map(mo => {
      const [y, m] = mo.split('-').map(Number);
      return { createdAt: { $gte: new Date(y, m - 1, 1), $lt: new Date(y, m, 1) } };
    });
  }
  if (types) {
    const typeList = types.split(',').map(t => t.trim()).filter(Boolean);
    if (typeList.length === 1) filter.type = typeList[0];
    else if (typeList.length > 1) filter.type = { $in: typeList };
  } else if (type && type !== 'all') {
    filter.type = type;
  }
  return filter;
}

async function withTxnOrFallback(fn) {
  const session = await mongoose.startSession();
  let needsFallback = false;
  try {
    await session.withTransaction(() => fn(session));
  } catch (err) {
    const noReplicaSet =
      (err?.message || '').includes('retryable writes') ||
      (err?.message || '').includes('Transaction numbers') ||
      (err?.message || '').includes('replica set');
    if (!noReplicaSet) throw err;
    needsFallback = true;
  } finally {
    await session.endSession();
  }
  if (needsFallback) await fn(null);
} // 1 🌶️ = $0.20

const PACKAGES = [
  { name: 'Chill Vibes', usd: 20,  chl: 100  },
  { name: 'After Hours', usd: 50,  chl: 250  },
  { name: 'Milky Way',   usd: 100, chl: 500  },
  { name: 'Inferno',     usd: 200, chl: 1000 },
];

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/signup');
  next();
}

// GET /wallet/topup
router.get('/topup', requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId).select('wallet').lean();
  res.render('app/wallet/topup', {
    title:      'Top Up',
    activePage: 'wallet',
    packages:   PACKAGES,
    balance:    (user?.wallet?.purchasedCHL || 0) + (user?.wallet?.earnedCHL || 0),
  });
});

// GET /wallet/checkout
router.get('/checkout', requireAuth, async (req, res) => {
  const { amount, package: pkgName, custom } = req.query;
  const amountCHL = parseInt(amount, 10);

  if (!amountCHL || amountCHL < 100) return res.redirect('/wallet/topup');

  const amountUSD = +(amountCHL * EXCHANGE_RATE).toFixed(2);
  const packageName = custom === 'true' ? null : (pkgName || null);

  const user = await User.findById(req.session.userId).select('wallet').lean();

  res.render('app/wallet/checkout', {
    title:       'Checkout',
    activePage:  'wallet',
    amountCHL,
    amountUSD,
    packageName,
    balance:     (user?.wallet?.purchasedCHL || 0) + (user?.wallet?.earnedCHL || 0),
  });
});

// POST /wallet/checkout — fake payment processing (CCBill stub)
router.post('/checkout', requireAuth, async (req, res) => {
  const { amountCHL: rawAmount, packageName } = req.body;
  const amountCHL = parseInt(rawAmount, 10);

  if (!amountCHL || amountCHL < 100) return res.redirect('/wallet/topup');

  const amountUSD = +(amountCHL * EXCHANGE_RATE).toFixed(2);
  const userId    = req.session.userId;

  try {
    await withTxnOrFallback(async (session) => {
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $inc: { 'wallet.purchasedCHL': amountCHL }, $set: { 'wallet.updatedAt': new Date() } },
        { new: true, select: 'wallet', session }
      );
      if (!updatedUser) throw new Error('User not found.');

      const balanceAfter  = (updatedUser.wallet.purchasedCHL || 0) + (updatedUser.wallet.earnedCHL || 0);
      const balanceBefore = balanceAfter - amountCHL;

      await WalletTransaction.create([{
        userId,
        type:          'top_up',
        direction:     'credit',
        amountCHL,
        amountUSD,
        exchangeRate:  EXCHANGE_RATE,
        balanceBefore,
        balanceAfter,
        status:        'completed',
        source:        packageName ? 'package' : 'custom',
        packageName:   packageName || undefined,
        metadata:      { userAgent: req.headers['user-agent'] },
      }], { session });
    });
  } catch (err) {
    console.error('Top-up transaction error:', err);
    return res.redirect('/wallet/topup?error=failed');
  }

  res.redirect('/settings?tab=wallet&success=topup');
});

// GET /wallet/transactions — full paginated transaction history
router.get('/transactions', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { month, type, months, types } = req.query;
  const filter = buildTxFilter(userId, month, type, months, types);

  const [transactions, transactionMonthsRaw] = await Promise.all([
    WalletTransaction.find(filter).sort({ createdAt: -1 }).lean(),
    WalletTransaction.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$createdAt' } } } },
      { $sort: { _id: -1 } },
    ]),
  ]);

  res.render('app/wallet/transactions', {
    title:      'Transaction History',
    activePage: 'settings',
    transactions,
    totalCount:        transactions.length,
    transactionMonths: transactionMonthsRaw.map(r => r._id),
    txLabels:          TX_LABELS,
    filterMonth:       month || '',
    filterType:        type  || '',
  });
});

// GET /wallet/transactions/download — Excel export of filtered transactions
router.get('/transactions/download', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { month, type, months, types } = req.query;
  const filter = buildTxFilter(userId, month, type, months, types);

  const transactions = await WalletTransaction.find(filter).sort({ createdAt: -1 }).lean();

  const rows = transactions.map(tx => ({
    Date:              new Date(tx.createdAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }),
    Type:              TX_LABELS[tx.type] || tx.type,
    Direction:         tx.direction === 'credit' ? 'Credit' : 'Debit',
    'Amount (CHL)':    tx.direction === 'credit' ? tx.amountCHL : -tx.amountCHL,
    'Amount (USD)':    tx.direction === 'credit' ? tx.amountUSD : -tx.amountUSD,
    'Balance After (CHL)': tx.balanceAfter,
    Status:            tx.status,
    Package:           tx.packageName || '',
  }));

  const ws  = XLSX.utils.json_to_sheet(rows);
  const wb  = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Transactions');

  const buf      = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  const filename = `transactions${month ? '-' + month : ''}${type && type !== 'all' ? '-' + type : ''}.xlsx`;

  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

// GET /wallet/transaction/:id — transaction detail page
router.get('/transaction/:id', requireAuth, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.redirect('/settings?tab=wallet');

  const tx = await WalletTransaction.findOne({ _id: req.params.id, userId: req.session.userId }).lean();
  if (!tx) return res.redirect('/settings?tab=wallet');

  let reference = null;
  if (tx.referenceId && tx.referenceType === 'Contest') {
    const Contest = require('../models/Contest');
    reference = await Contest.findById(tx.referenceId).select('entries status').lean();
  } else if (tx.referenceId && tx.referenceType === 'ContestContribution') {
    const ContestContribution = require('../models/ContestContribution');
    const contrib = await ContestContribution.findById(tx.referenceId)
      .select('contestId entryId amountCHL status')
      .lean();
    if (contrib) reference = { ...contrib, _type: 'ContestContribution' };
  }

  res.render('app/wallet/transaction', {
    title:      'Transaction Detail',
    activePage: 'settings',
    tx,
    reference,
  });
});

// POST /wallet/hold-payout — hold current month's auto-payout until the 15th
router.post('/hold-payout', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const today  = new Date().getDate();

  if (today < 25 || today > 29) return res.redirect('/settings?tab=wallet');

  const currentMonth = new Date().toISOString().slice(0, 7);
  const snapshot = await MonthlySnapshot.findOne({ userId, month: currentMonth, status: 'pending' });
  if (!snapshot) return res.redirect('/settings?tab=wallet');

  snapshot.status = 'held';
  snapshot.heldAt = new Date();
  await snapshot.save();

  res.redirect('/settings?tab=wallet');
});

return router;
}

// ── Direct messages ───────────────────────────────────────────────────────
function messagesRoutes() {
const express         = require('express');
const router          = express.Router();
const mongoose        = require('mongoose');
const User            = require('../models/User');
const Conversation    = require('../models/Conversation');
const DirectMessage   = require('../models/DirectMessage');
const requireAuth     = require('../middleware/requireAuth');
const requireApproved = require('../middleware/requireApproved');

router.use(requireAuth);
router.use(requireApproved);

// ── Helpers ────────────────────────────────────────────────────────────────

function sortedIds(a, b) {
  const sa = a.toString(), sb = b.toString();
  return sa < sb ? [sa, sb] : [sb, sa];
}

async function findOrCreateConversation(idA, idB) {
  const [p0, p1] = sortedIds(idA, idB);
  let conv = await Conversation.findOne({
    'participants.0': p0,
    'participants.1': p1,
  });
  if (!conv) {
    conv = await Conversation.create({ participants: [p0, p1] });
  }
  return conv;
}

async function getConversationsForUser(userId) {
  const convs = await Conversation.find({ participants: userId })
    .sort({ lastMessageAt: -1 })
    .lean();
  if (!convs.length) return [];

  const otherIds = convs.map(c =>
    c.participants.find(p => p.toString() !== userId.toString())
  );
  const convIds = convs.map(c => c._id);

  const [users, unreadAgg] = await Promise.all([
    User.find({ _id: { $in: otherIds } })
      .select('username displayName avatar')
      .lean(),
    DirectMessage.aggregate([
      {
        $match: {
          conversationId:  { $in: convIds },
          senderId:        { $nin: [new mongoose.Types.ObjectId(userId)] },
          readByRecipient: false,
        },
      },
      { $group: { _id: '$conversationId', count: { $sum: 1 } } },
    ]),
  ]);

  const userMap = {};
  users.forEach(u => { userMap[u._id.toString()] = u; });
  const unreadMap = {};
  unreadAgg.forEach(u => { unreadMap[u._id.toString()] = u.count; });

  return convs.map(c => {
    const otherId = c.participants.find(p => p.toString() !== userId.toString());
    return {
      ...c,
      otherUser:   userMap[otherId.toString()] || null,
      unreadCount: unreadMap[c._id.toString()] || 0,
    };
  });
}

// ── Routes ─────────────────────────────────────────────────────────────────

// GET /messages
router.get('/', async (req, res) => {
  try {
    const conversations = await getConversationsForUser(req.session.userId);
    res.render('app/messages', {
      title:           'Messages',
      activePage:      'messages',
      currentUser:     req.currentUser,
      conversations,
      activeConv:      null,
      otherUser:       null,
      initialMessages: [],
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading messages');
  }
});

// GET /messages/:username — open or create conversation
router.get('/:username', async (req, res) => {
  try {
    const other = await User.findOne({ 'username.value': req.params.username.toLowerCase() })
      .select('username displayName avatar _id')
      .lean();
    if (!other) return res.redirect('/messages');
    if (other._id.toString() === req.session.userId) return res.redirect('/messages');

    const conv = await findOrCreateConversation(req.session.userId, other._id);

    const [messages, conversations] = await Promise.all([
      DirectMessage.find({ conversationId: conv._id }).sort({ createdAt: 1 }).lean(),
      getConversationsForUser(req.session.userId),
      DirectMessage.updateMany(
        { conversationId: conv._id, senderId: other._id, readByRecipient: false },
        { $set: { readByRecipient: true } }
      ),
    ]);

    const displayName = other.displayName?.value || ('@' + other.username?.value);

    res.render('app/messages', {
      title:           `Messages · ${displayName}`,
      activePage:      'messages',
      currentUser:     req.currentUser,
      conversations,
      activeConv:      conv,
      otherUser:       other,
      initialMessages: messages,
    });
  } catch (err) {
    console.error(err);
    res.redirect('/messages');
  }
});

// GET /messages/:username/history — JSON poll
router.get('/:username/history', async (req, res) => {
  try {
    const other = await User.findOne({ 'username.value': req.params.username.toLowerCase() })
      .select('_id')
      .lean();
    if (!other) return res.status(404).json({ error: 'User not found' });

    const [p0, p1] = sortedIds(req.session.userId, other._id);
    const conv = await Conversation.findOne({ 'participants.0': p0, 'participants.1': p1 }).lean();
    if (!conv) return res.json({ messages: [] });

    const messages = await DirectMessage.find({ conversationId: conv._id })
      .sort({ createdAt: 1 })
      .lean();

    await DirectMessage.updateMany(
      { conversationId: conv._id, senderId: other._id, readByRecipient: false },
      { $set: { readByRecipient: true } }
    );

    res.json({ messages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});

// POST /messages/:username/send
router.post('/:username/send', async (req, res) => {
  try {
    const other = await User.findOne({ 'username.value': req.params.username.toLowerCase() })
      .select('_id')
      .lean();
    if (!other) return res.status(404).json({ error: 'User not found' });
    if (other._id.toString() === req.session.userId) {
      return res.status(400).json({ error: 'Cannot message yourself' });
    }

    const body = (req.body.body || '').trim().slice(0, 500);
    if (!body) return res.status(400).json({ error: 'Message cannot be empty' });

    const conv = await findOrCreateConversation(req.session.userId, other._id);

    const msg = await DirectMessage.create({
      conversationId:  conv._id,
      senderId:        req.session.userId,
      body,
      readByRecipient: false,
    });

    await Conversation.findByIdAndUpdate(conv._id, {
      lastMessageAt:   new Date(),
      lastMessageBody: body.slice(0, 80),
      lastSenderId:    req.session.userId,
    });

    res.json({ message: msg });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

return router;
}

// ── Notifications ─────────────────────────────────────────────────────────
function notificationsRoutes() {
const express      = require('express');
const router       = express.Router();
const mongoose     = require('mongoose');
const requireAuth  = require('../middleware/requireAuth');
const requireApproved = require('../middleware/requireApproved');
const Notification = require('../models/Notification');
const Nomination   = require('../models/Nomination');
const Entry        = require('../models/Entry');

router.use(requireAuth);
router.use(requireApproved);

router.get('/', async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 30;
  const skip  = (page - 1) * limit;

  const [notifications, total] = await Promise.all([
    Notification.find({ userId: req.session.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    Notification.countDocuments({ userId: req.session.userId }),
  ]);

  // Enrich take_on_received notifications that predate the media URL payload fields
  const stale = notifications.filter(n => n.type === 'take_on_received' && n.payload?.nominationId && !n.payload.challengerEntryUrl);
  if (stale.length) {
    const nomIds = stale.map(n => n.payload.nominationId).filter(Boolean);
    const noms   = await Nomination.find({ _id: { $in: nomIds } })
      .select('_id challengerEntryId nomineeEntryId').lean().catch(() => []);
    const nomMap = {};
    noms.forEach(nom => { nomMap[nom._id.toString()] = nom; });

    const entryIds = noms.flatMap(nom => [nom.challengerEntryId, nom.nomineeEntryId]).filter(Boolean);
    const entries  = entryIds.length
      ? await Entry.find({ _id: { $in: entryIds } }).select('_id mediaUrl mediaType').lean().catch(() => [])
      : [];
    const entryMap = {};
    entries.forEach(e => { entryMap[e._id.toString()] = e; });

    for (const n of stale) {
      const nom = nomMap[n.payload.nominationId?.toString()];
      if (!nom) continue;
      const ce = nom.challengerEntryId ? entryMap[nom.challengerEntryId.toString()] : null;
      const ne = nom.nomineeEntryId    ? entryMap[nom.nomineeEntryId.toString()]    : null;
      if (ce) { n.payload.challengerEntryUrl  = ce.mediaUrl;  n.payload.challengerEntryType = ce.mediaType; }
      if (ne) { n.payload.nomineeEntryUrl     = ne.mediaUrl;  n.payload.nomineeEntryType    = ne.mediaType; }
    }
  }

  res.render('app/notifications', {
    title: 'Notifications',
    activePage: 'notifications',
    currentUser: req.currentUser,
    notifications,
    page,
    hasMore: skip + notifications.length < total,
  });
});

router.post('/:id/read', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }
  const notif = await Notification.findOneAndUpdate(
    { _id: req.params.id, userId: req.session.userId },
    { read: true },
    { new: true },
  ).lean();

  if (!notif) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true, url: notif.payload?.url || '/notifications' });
});

router.post('/read-all', async (req, res) => {
  await Notification.updateMany({ userId: req.session.userId, read: false }, { read: true });
  res.json({ ok: true });
});

return router;
}

// ── Explore ───────────────────────────────────────────────────────────────
function exploreRoutes() {
const express             = require('express');
const router              = express.Router();
const Entry               = require('../models/Entry');
const Rating              = require('../models/Rating');
const Comment             = require('../models/Comment');
const Contest             = require('../models/Contest');
const Follow              = require('../models/Follow');
const User                = require('../models/User');
const UserBlock           = require('../models/UserBlock');
const UserAffinity        = require('../models/UserAffinity');
const TournamentEntry     = require('../models/TournamentEntry');
const ContestContribution = require('../models/ContestContribution');
const ContestVote         = require('../models/ContestVote');
const requireAuth         = require('../middleware/requireAuth');
const requireApproved     = require('../middleware/requireApproved');
const { buildExploreEntryBlock, BLOCK_SIZE } = require('../services/exploreScorer');
const { getTrendingStains }                  = require('../services/stainPopularity');

router.use(requireAuth);
router.use(requireApproved);

const CANDIDATE_POOL    = 150;
const BLOCKS_PER_LOAD   = 5;
const MIN_SECTION_USERS = 3;

async function buildScoringContext(currentUserId, candidates, follows, affinityDoc) {
  const ids         = candidates.map(e => e._id);
  const sixHoursAgo = new Date(Date.now() - 6  * 60 * 60 * 1000);
  const oneDayAgo   = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const followingSet = new Set(follows.map(f => f.followingId.toString()));

  const [myRatings, ratingVelocityAgg, commentVelocityAgg, activity24hAgg, activeContests] = await Promise.all([
    Rating.find({ userId: currentUserId, entryId: { $in: ids } }).select('entryId score').lean(),
    Rating.aggregate([
      { $match: { entryId: { $in: ids }, createdAt: { $gte: sixHoursAgo } } },
      { $group: { _id: '$entryId', count: { $sum: 1 } } },
    ]),
    Comment.aggregate([
      { $match: { entryId: { $in: ids }, createdAt: { $gte: sixHoursAgo } } },
      { $group: { _id: '$entryId', count: { $sum: 1 } } },
    ]),
    Promise.all([
      Rating.aggregate([
        { $match: { entryId: { $in: ids }, createdAt: { $gte: oneDayAgo } } },
        { $group: { _id: '$entryId', count: { $sum: 1 } } },
      ]),
      Comment.aggregate([
        { $match: { entryId: { $in: ids }, createdAt: { $gte: oneDayAgo } } },
        { $group: { _id: '$entryId', count: { $sum: 1 } } },
      ]),
    ]),
    Contest.find({ 'entries.entryId': { $in: ids }, status: 'active' }).select('entries').lean(),
  ]);

  const ratedMap = {};
  for (const r of myRatings) ratedMap[r.entryId.toString()] = r.score;

  const ratingVelocityMap = {};
  for (const v of ratingVelocityAgg) ratingVelocityMap[v._id.toString()] = v.count;

  const commentVelocityMap = {};
  for (const v of commentVelocityAgg) commentVelocityMap[v._id.toString()] = v.count;

  const activity24hMap = {};
  const [ratings24h, comments24h] = activity24hAgg;
  for (const v of ratings24h)  activity24hMap[v._id.toString()] = (activity24hMap[v._id.toString()] || 0) + v.count;
  for (const v of comments24h) activity24hMap[v._id.toString()] = (activity24hMap[v._id.toString()] || 0) + v.count;

  const inActiveContestSet = new Set();
  for (const c of activeContests) {
    for (const e of c.entries) inActiveContestSet.add(e.entryId.toString());
  }

  const stainScores   = affinityDoc?.stainScores   instanceof Map ? affinityDoc.stainScores   : new Map(Object.entries(affinityDoc?.stainScores   || {}));
  const creatorScores = affinityDoc?.creatorScores instanceof Map ? affinityDoc.creatorScores : new Map(Object.entries(affinityDoc?.creatorScores || {}));

  return {
    followingSet, ratedMap,
    ratingVelocityMap, commentVelocityMap,
    activity24hMap, inActiveContestSet,
    stainScores, creatorScores,
  };
}

async function getPeopleSubSections(currentUserId, followingSet, previewSize = 3) {
  const twoDaysAgo  = new Date(Date.now() - 48 * 60 * 60 * 1000);
  const excludeSet  = new Set([currentUserId.toString(), ...followingSet]);
  const FETCH_LIMIT = 20;

  const [
    trendingAgg,
    topRatedAgg,
    activeContests,
    tournamentIds,
    topContributorsAgg,
    mostVotedAgg,
  ] = await Promise.all([
    Follow.aggregate([
      { $match: { createdAt: { $gte: twoDaysAgo } } },
      { $group: { _id: '$followingId', newFollowers: { $sum: 1 } } },
      { $sort: { newFollowers: -1 } },
      { $limit: FETCH_LIMIT },
    ]),
    Entry.aggregate([
      { $match: { hidden: false, ratingCount: { $gte: 3 } } },
      { $group: { _id: '$userId', avgRating: { $avg: '$ratingAvg' }, entryCount: { $sum: 1 } } },
      { $match: { entryCount: { $gte: 3 } } },
      { $sort: { avgRating: -1 } },
      { $limit: FETCH_LIMIT },
    ]),
    Contest.find({
      updatedAt: { $gte: twoDaysAgo },
      status: { $in: ['active', 'closed'] },
    }).select('entries').lean(),
    TournamentEntry.distinct('userId', {
      createdAt:      { $gte: twoDaysAgo },
      approvalStatus: 'approved',
    }),
    ContestContribution.aggregate([
      { $match: { createdAt: { $gte: twoDaysAgo }, status: { $in: ['active', 'locked'] } } },
      { $group: { _id: '$contributorId', totalCHL: { $sum: '$amountCHL' } } },
      { $sort: { totalCHL: -1 } },
      { $limit: FETCH_LIMIT },
    ]),
    ContestVote.aggregate([
      { $match: { createdAt: { $gte: twoDaysAgo } } },
      { $group: { _id: '$entryId', voteCount: { $sum: 1 } } },
      { $lookup: { from: 'entries', localField: '_id', foreignField: '_id', as: 'entry' } },
      { $unwind: '$entry' },
      { $group: { _id: '$entry.userId', totalVotes: { $sum: '$voteCount' } } },
      { $sort: { totalVotes: -1 } },
      { $limit: FETCH_LIMIT },
    ]),
  ]);

  const contestParticipantIds = [];
  for (const c of activeContests) {
    for (const e of c.entries || []) contestParticipantIds.push(e.userId.toString());
  }
  const uniqueContestIds = [...new Set(contestParticipantIds)];

  const rawSections = [
    { label: 'Trending Profiles',       userIds: trendingAgg.map(r => r._id.toString()),         key: 'trending' },
    { label: 'Top Rated',               userIds: topRatedAgg.map(r => r._id.toString()),          key: 'top_rated' },
    { label: 'Active in Contests',      userIds: uniqueContestIds,                                key: 'active_contests' },
    { label: 'Tournament Participants', userIds: tournamentIds.map(id => id.toString()),           key: 'tournaments' },
    { label: 'Top Contributors',        userIds: topContributorsAgg.map(r => r._id.toString()),   key: 'contributors' },
    { label: 'Most Voted',              userIds: mostVotedAgg.map(r => r._id.toString()),         key: 'most_voted' },
  ];

  const allUserIds = [...new Set(rawSections.flatMap(s => s.userIds))].filter(id => !excludeSet.has(id));
  if (!allUserIds.length) return [];

  const users = await User.find({ _id: { $in: allUserIds }, accountStatus: 'active' })
    .select('username displayName avatar')
    .lean();

  const userMap = {};
  for (const u of users) userMap[u._id.toString()] = u;

  const sections = [];
  for (const section of rawSections) {
    const sectionUsers = section.userIds
      .filter(id => !excludeSet.has(id) && userMap[id])
      .slice(0, FETCH_LIMIT)
      .map(id => userMap[id]);

    if (sectionUsers.length >= MIN_SECTION_USERS) {
      sections.push({ ...section, users: sectionUsers.slice(0, previewSize), allCount: sectionUsers.length });
    }
  }

  return sections;
}

// ── Initial page load ──────────────────────────────────────────────────────────
router.get('/explore', async (req, res) => {
  const currentUserId = req.session.userId;

  const [blockDocs, follows, affinityDoc] = await Promise.all([
    UserBlock.find({ blockerId: currentUserId }).select('blockedId').lean(),
    Follow.find({ followerId: currentUserId }).select('followingId').lean(),
    UserAffinity.findOne({ userId: currentUserId }).lean(),
  ]);

  const blockedIds  = blockDocs.map(b => b.blockedId);
  const blockedSet  = new Set(blockedIds.map(id => id.toString()));

  const candidates = await Entry.find({ userId: { $ne: currentUserId, $nin: blockedIds }, hidden: false })
    .sort({ createdAt: -1 })
    .limit(CANDIDATE_POOL)
    .populate('userId', 'username displayName avatar')
    .lean();

  const scoringContext = await buildScoringContext(currentUserId, candidates, follows, affinityDoc);

  const excludeSet = new Set([...scoringContext.followingSet, ...blockedSet]);

  const [trendingStains, peopleSections] = await Promise.all([
    getTrendingStains({ limit: 30 }),
    getPeopleSubSections(currentUserId, excludeSet),
  ]);

  const servedIds   = new Set();
  const stainQueue  = [...trendingStains];
  const peopleQueue = [...peopleSections];
  const sections    = [];

  for (let i = 0; i < BLOCKS_PER_LOAD; i++) {
    const remaining = candidates.filter(e => !servedIds.has(e._id.toString()));
    const block     = buildExploreEntryBlock(remaining, scoringContext, req.currentUser, BLOCK_SIZE);

    if (block.length) {
      block.forEach(e => servedIds.add(e._id.toString()));
      sections.push({ type: 'entries', entries: block });
    }

    if (i % 2 === 0 && stainQueue.length) {
      sections.push({ type: 'stains', stains: stainQueue.splice(0, 10) });
    } else if (peopleQueue.length) {
      sections.push({ type: 'people', ...peopleQueue.shift() });
    } else if (stainQueue.length) {
      sections.push({ type: 'stains', stains: stainQueue.splice(0, 10) });
    }
  }

  res.render('app/explore', {
    title:       'Explore',
    activePage:  'explore',
    currentUser: req.currentUser,
    sections,
  });
});

// ── Infinite scroll — next block of entries ────────────────────────────────────
router.get('/api/explore/entries', async (req, res) => {
  const page          = Math.max(1, parseInt(req.query.page, 10) || 1);
  const currentUserId = req.session.userId;

  const [blockDocs, follows, affinityDoc] = await Promise.all([
    UserBlock.find({ blockerId: currentUserId }).select('blockedId').lean(),
    Follow.find({ followerId: currentUserId }).select('followingId').lean(),
    UserAffinity.findOne({ userId: currentUserId }).lean(),
  ]);

  const blockedIds = blockDocs.map(b => b.blockedId);

  const candidates = await Entry.find({ userId: { $ne: currentUserId, $nin: blockedIds }, hidden: false })
    .sort({ createdAt: -1 })
    .skip(page * CANDIDATE_POOL)
    .limit(CANDIDATE_POOL)
    .populate('userId', 'username displayName avatar')
    .lean();

  if (!candidates.length) return res.json({ html: '', hasMore: false });

  const scoringContext = await buildScoringContext(currentUserId, candidates, follows, affinityDoc);
  const block          = buildExploreEntryBlock(candidates, scoringContext, req.currentUser, BLOCK_SIZE);

  if (!block.length) return res.json({ html: '', hasMore: false });

  res.render('app/partials/exploreEntryBlock', { entries: block, currentUser: req.currentUser }, (err, html) => {
    if (err) return res.json({ html: '', hasMore: false });
    res.json({ html, hasMore: block.length >= BLOCK_SIZE });
  });
});

router.getPeopleSubSections = getPeopleSubSections;
return router;
}

// ── Tournaments ───────────────────────────────────────────────────────────
function tournamentsRoutes() {
const express    = require('express');
const router     = express.Router();
const mongoose   = require('mongoose');
const User                        = require('../models/User');
const Tournament                  = require('../models/Tournament');
const TournamentEntry             = require('../models/TournamentEntry');
const TournamentGroup             = require('../models/TournamentGroup');
const TournamentMatch             = require('../models/TournamentMatch');
const ContestVote                 = require('../models/ContestVote');
const TournamentJury              = require('../models/TournamentJury');
const TournamentJuryVote          = require('../models/TournamentJuryVote');
const TournamentGroupTieVote      = require('../models/TournamentGroupTieVote');
const TournamentComment           = require('../models/TournamentComment');
const TournamentCommentReport     = require('../models/TournamentCommentReport');
const TournamentReport            = require('../models/TournamentReport');
const TournamentLoop               = require('../models/TournamentLoop');
const TournamentEntryLoop          = require('../models/TournamentEntryLoop');
const WalletTransaction           = require('../models/WalletTransaction');
const Notification                = require('../models/Notification');
const Follow                      = require('../models/Follow');
const Nomination                  = require('../models/Nomination');
const requireAuth                 = require('../middleware/requireAuth');
const requireApproved             = require('../middleware/requireApproved');
const requireOrganizerEligibility = require('../middleware/requireOrganizerEligibility');
const upload                      = require('../middleware/upload');
const { CRITERIA_FIELDS, CRITERIA_OPERATORS, SEX_VALUES } = require('../services/tournamentCriteria');
const { creditWallet } = require('../services/wallet');
const estimateParticipantPool = require('../services/estimateParticipantPool');
const { cancelTournament } = require('../services/jobs/tournamentJobs');

const EXCHANGE_RATE = 0.20;

const GROUP_CONFIG = {
  4:  { groupSize: 4, groupCount: 1 },
  8:  { groupSize: 4, groupCount: 2 },
  12: { groupSize: 3, groupCount: 4 },
  16: { groupSize: 4, groupCount: 4 },
  24: { groupSize: 3, groupCount: 8 },
};

router.use(requireAuth);
router.use(requireApproved);

// ── GET /tournaments — list ────────────────────────────────────────────────
router.get('/tournaments', async (req, res) => {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const visibilityFilter = { $or: [{ visibility: 'public' }, { visibility: { $exists: false } }, { createdBy: req.currentUser._id }] };

  const [liveTournaments, closedTournaments] = await Promise.all([
    Tournament.find({ status: { $in: ['open', 'cooldown', 'active'] }, ...visibilityFilter })
      .sort({ createdAt: -1 })
      .limit(20)
      .populate('createdBy', 'username displayName avatar')
      .lean(),
    Tournament.find({ status: 'closed', updatedAt: { $gte: thirtyDaysAgo }, ...visibilityFilter })
      .sort({ updatedAt: -1 })
      .limit(5)
      .populate('createdBy', 'username displayName avatar')
      .lean(),
  ]);

  const currentUserId = req.currentUser._id;
  const organizerIds = [...liveTournaments, ...closedTournaments]
    .map(t => t.createdBy?._id)
    .filter(Boolean);
  const followDocs = organizerIds.length
    ? await Follow.find({ followerId: currentUserId, followingId: { $in: organizerIds } }).select('followingId').lean()
    : [];
  const followingSet = new Set(followDocs.map(f => f.followingId.toString()));
  [...liveTournaments, ...closedTournaments].forEach(t => {
    const uid = t.createdBy?._id?.toString();
    t.isFollowing = uid ? followingSet.has(uid) : false;
    t.isSelf      = uid === currentUserId.toString();
  });

  const openTournaments   = liveTournaments.filter(t => t.status === 'open' || t.status === 'cooldown');
  const activeTournaments = liveTournaments.filter(t => t.status === 'active');

  await Promise.all([
    attachSpotsFilled(openTournaments),
    attachProgressLabel(activeTournaments),
    attachWinners(closedTournaments),
  ]);

  res.render('app/tournaments/index', {
    title:      'Tournaments',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    openTournaments,
    activeTournaments,
    closedTournaments,
    draft: req.session.tournamentDraft || null,
    flash: req.query.flash || null,
    flashType: req.query.flashType === 'error' ? 'error' : 'success',
  });
});

// Mutates each open/cooldown tournament with `spotsFilled` — candidates submitted (open) or
// approved (cooldown, since organizer batch-review is what actually fills the cap) — out of `size`.
async function attachSpotsFilled(tournaments) {
  if (!tournaments.length) return;
  const rows = await TournamentEntry.aggregate([
    { $match: { tournamentId: { $in: tournaments.map(t => t._id) }, approvalStatus: { $in: ['pending', 'approved'] } } },
    { $group: { _id: { tournamentId: '$tournamentId', approvalStatus: '$approvalStatus' }, count: { $sum: 1 } } },
  ]);
  const countsByTournament = {};
  rows.forEach(row => {
    const tid = row._id.tournamentId.toString();
    (countsByTournament[tid] = countsByTournament[tid] || { pending: 0, approved: 0 })[row._id.approvalStatus] = row.count;
  });
  tournaments.forEach(t => {
    const c = countsByTournament[t._id.toString()] || { pending: 0, approved: 0 };
    t.spotsFilled = t.status === 'cooldown' ? c.approved : (c.pending + c.approved);
  });
}

const KNOCKOUT_ROUNDS = ['R16', 'QF', 'SF'];
const KNOCKOUT_ROUND_LABELS = { R16: 'Round of 16', QF: 'Quarterfinal', SF: 'Semifinal', Final: 'Final' };

// Mutates each active tournament with `progressLabel` — "Group Stage · X/Y played" while in the
// group stage, or the current knockout round name (3rd + Final run together, so both map to "Final").
async function attachProgressLabel(tournaments) {
  if (!tournaments.length) return;
  const matches = await TournamentMatch.find({ tournamentId: { $in: tournaments.map(t => t._id) } })
    .select('tournamentId stage knockoutRound status')
    .lean();
  const matchesByTournament = {};
  matches.forEach(m => {
    const tid = m.tournamentId.toString();
    (matchesByTournament[tid] = matchesByTournament[tid] || []).push(m);
  });
  tournaments.forEach(t => {
    const tMatches = matchesByTournament[t._id.toString()] || [];
    if (t.stage === 'group') {
      const groupMatches = tMatches.filter(m => m.stage === 'group');
      const closed = groupMatches.filter(m => m.status === 'closed').length;
      t.progressLabel = groupMatches.length ? `Group Stage · ${closed}/${groupMatches.length} played` : 'Group Stage';
      return;
    }
    const knockoutMatches = tMatches.filter(m => m.stage === 'knockout');
    const hasFinale = knockoutMatches.some(m => m.knockoutRound === 'Final' || m.knockoutRound === '3rd');
    let currentRound = null;
    if (hasFinale) {
      currentRound = 'Final';
    } else {
      currentRound = KNOCKOUT_ROUNDS.find(r => {
        const roundMatches = knockoutMatches.filter(m => m.knockoutRound === r);
        return roundMatches.length && roundMatches.some(m => m.status !== 'closed');
      });
      if (!currentRound) {
        const reached = knockoutMatches.map(m => m.knockoutRound);
        currentRound = KNOCKOUT_ROUNDS.filter(r => reached.includes(r)).pop() || null;
      }
    }
    t.progressLabel = currentRound ? KNOCKOUT_ROUND_LABELS[currentRound] : 'Knockout';
  });
}

// Mutates each closed tournament with `winner` (populated TournamentEntry of the Final match's
// winner) — batched across all closed tournaments in one pass rather than per-tournament, since
// this runs on the browse list. Mirrors the single-tournament logic in loadTournamentPlacements.
async function attachWinners(tournaments) {
  if (!tournaments.length) return;
  const finals = await TournamentMatch.find({ tournamentId: { $in: tournaments.map(t => t._id) }, knockoutRound: 'Final' })
    .select('tournamentId entryIdA entryIdB winnerId tournamentEntryIdA tournamentEntryIdB')
    .lean();
  const winnerTeIdByTournament = {};
  finals.forEach(m => {
    if (!m.winnerId) return;
    winnerTeIdByTournament[m.tournamentId.toString()] =
      m.entryIdA.toString() === m.winnerId.toString() ? m.tournamentEntryIdA : m.tournamentEntryIdB;
  });
  const winnerTeIds = Object.values(winnerTeIdByTournament);
  if (!winnerTeIds.length) return;
  const winnerEntries = await TournamentEntry.find({ _id: { $in: winnerTeIds } })
    .populate('userId', 'username displayName avatar')
    .lean();
  const winnerEntryById = {};
  winnerEntries.forEach(e => { winnerEntryById[e._id.toString()] = e; });
  tournaments.forEach(t => {
    const teId = winnerTeIdByTournament[t._id.toString()];
    t.winner = teId ? winnerEntryById[teId.toString()] || null : null;
  });
}

// ── GET /tournaments/create — resume at last-visited step, or start fresh ──
// `?new=1` (the "+" FAB) explicitly discards any in-progress draft first — resuming is only
// for the "Draft" tab's "tap to resume" card, which links here without that flag.
router.get('/tournaments/create', requireOrganizerEligibility, (req, res) => {
  if (req.query.new === '1') delete req.session.tournamentDraft;

  const draftStep = req.session.tournamentDraft?.step;
  if (draftStep && draftStep > 1) {
    return res.redirect(`/tournaments/create/step${draftStep}`);
  }
  res.render('app/tournaments/create', {
    title:      'Create Tournament',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    step:     1,
    maxStep:  req.session.tournamentDraft?.maxStep || 1,
    errors:   [],
    formData: req.session.tournamentDraft || {},
  });
});

// ── GET /tournaments/create/step1 — explicit revisit (back navigation) ─────
router.get('/tournaments/create/step1', requireOrganizerEligibility, (req, res) => {
  res.render('app/tournaments/create', {
    title:      'Create Tournament',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    step:     1,
    maxStep:  req.session.tournamentDraft?.maxStep || 1,
    errors:   [],
    formData: req.session.tournamentDraft || {},
  });
});

// ── POST /tournaments/create/step1 — Basics ────────────────────────────────
// Trim/lowercase/dedupe stains the same way entry tags are normalized, capped at 6.
function normalizeStains(raw) {
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return [...new Set(list.map(s => s.trim().toLowerCase()).filter(Boolean))].slice(0, 6);
}

// Trim/lowercase/dedupe wildcard stains the same way general stains are, capped at 2.
function normalizeWildcardStains(raw) {
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return [...new Set(list.map(s => s.trim().toLowerCase()).filter(Boolean))].slice(0, 2);
}

router.post('/tournaments/create/step1', requireOrganizerEligibility, upload.tournament.single('thumbnail'), async (req, res) => {
  const name        = (req.body.name || '').trim();
  const description = (req.body.description || '').trim();
  const size        = parseInt(req.body.size, 10);
  const openDays    = parseInt(req.body.openDays, 10);
  const visibility  = req.body.visibility === 'private' ? 'private' : 'public';
  const stains      = normalizeStains(req.body.stains);
  const wildcardStains = normalizeWildcardStains(req.body.wildcardStains);

  const thumbnailUrl = req.file
    ? '/uploads/tournaments/' + req.file.filename
    : req.body.removeThumbnail === '1'
      ? null
      : (req.session.tournamentDraft?.thumbnailUrl || null);

  if (req.body.intent === 'draft') {
    req.session.tournamentDraft = {
      ...(req.session.tournamentDraft || {}),
      name, description, thumbnailUrl, visibility, stains, wildcardStains,
      size:     Number.isInteger(size) ? size : undefined,
      openDays: Number.isInteger(openDays) ? openDays : undefined,
      step: 1,
    };
    return res.redirect('/tournaments?flash=' + encodeURIComponent('Draft saved.'));
  }

  const errors = [];
  if (!thumbnailUrl) {
    errors.push('A tournament thumbnail is required.');
  }
  if (name.length < 3 || name.length > 60) {
    errors.push('Tournament name must be between 3 and 60 characters.');
  }
  if (name && !/^[A-Za-z0-9 ]+$/.test(name)) {
    errors.push('Tournament name may only contain letters, numbers, and spaces.');
  }
  if (![4, 8, 12, 16, 24].includes(size)) {
    errors.push('Participant count must be 4, 8, 12, 16, or 24.');
  }
  if (![1, 2, 3].includes(openDays)) {
    errors.push('Open phase must last 1 to 3 days.');
  }
  if (description.length > 220) {
    errors.push('Description must be 220 characters or fewer.');
  }
  if (name.length >= 3 && name.length <= 60) {
    const existing = await Tournament.findOne({
      name: { $regex: '^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', $options: 'i' },
    }).select('_id').lean();
    if (existing) errors.push('A tournament with this name already exists.');
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 1, maxStep: req.session.tournamentDraft?.maxStep || 1, errors,
      formData: { name, description, size: req.body.size, openDays: req.body.openDays, thumbnailUrl, visibility, stains, wildcardStains },
    });
  }

  const maxStep = Math.max(2, req.session.tournamentDraft?.maxStep || 1);
  req.session.tournamentDraft = {
    ...(req.session.tournamentDraft || {}),
    name, description, size, openDays, thumbnailUrl, visibility, stains, wildcardStains,
    step: 2, maxStep,
  };
  res.redirect('/tournaments/create/step2');
});

// ── GET /tournaments/create/step2 — Prizes + Inline Funding ────────────────
router.get('/tournaments/create/step2', requireOrganizerEligibility, async (req, res) => {
  if (!req.session.tournamentDraft) return res.redirect('/tournaments/create');

  const user   = await User.findById(req.currentUser._id).select('wallet').lean();
  const prizes = req.session.tournamentDraft.prizes || {};
  res.render('app/tournaments/create', {
    title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 2, maxStep: req.session.tournamentDraft.maxStep || 2, sbBalance: user?.wallet?.purchasedCHL || 0, errors: [],
    formData: { prizeFirst: prizes.first, prizeSecond: prizes.second, prizeThird: prizes.third },
  });
});

// ── POST /tournaments/create/step2 ─────────────────────────────────────────
router.post('/tournaments/create/step2', requireOrganizerEligibility, async (req, res) => {
  if (!req.session.tournamentDraft) return res.redirect('/tournaments/create');

  const prizeFirst  = parseInt(req.body.prizeFirst, 10);
  const prizeSecond = parseInt(req.body.prizeSecond, 10);
  const prizeThird  = parseInt(req.body.prizeThird, 10);

  if (req.body.intent === 'draft') {
    req.session.tournamentDraft.prizes = {
      first:  Number.isInteger(prizeFirst)  ? prizeFirst  : undefined,
      second: Number.isInteger(prizeSecond) ? prizeSecond : undefined,
      third:  Number.isInteger(prizeThird)  ? prizeThird  : undefined,
    };
    req.session.tournamentDraft.step = 2;
    return res.redirect('/tournaments?flash=' + encodeURIComponent('Draft saved.'));
  }

  const errors = [];
  if (!(prizeFirst >= 350))   errors.push('1st place prize must be at least 350 CHL.');
  if (!(prizeSecond >= 100))  errors.push('2nd place prize must be at least 100 CHL.');
  if (!(prizeThird >= 50))    errors.push('3rd place prize must be at least 50 CHL.');
  if (!errors.length) {
    if (!(prizeFirst > prizeSecond)) errors.push('1st place prize must be greater than 2nd place.');
    if (!(prizeSecond > prizeThird)) errors.push('2nd place prize must be greater than 3rd place.');
  }

  const user = await User.findById(req.currentUser._id).select('wallet').lean();
  const sbBalance = user?.wallet?.purchasedCHL || 0;
  const maxStep = req.session.tournamentDraft.maxStep || 2;

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 2, maxStep, sbBalance, errors, formData: { prizeFirst: req.body.prizeFirst, prizeSecond: req.body.prizeSecond, prizeThird: req.body.prizeThird },
    });
  }

  const total = prizeFirst + prizeSecond + prizeThird;

  if (sbBalance >= total) {
    req.session.tournamentDraft.prizes = { first: prizeFirst, second: prizeSecond, third: prizeThird };
    req.session.tournamentDraft.step = 3;
    req.session.tournamentDraft.maxStep = Math.max(3, maxStep);
    return res.redirect('/tournaments/create/step3');
  }

  const shortfall = total - sbBalance;
  res.render('app/tournaments/create', {
    title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 2, maxStep, sbBalance, errors: [], formData: { prizeFirst, prizeSecond, prizeThird },
    insufficientFunds: true, shortfall, total,
  });
});

// ── POST /tournaments/fund — inline tournament-gated top-up (CCBill stub) ──
// Shared by both the create wizard (requires fresh organizer eligibility) and the edit wizard
// (the tournament already exists, so re-checking eligibility here would wrongly count it against
// its own organizer's concurrent-tournament cap) — whichever draft is in session decides the redirect.
router.post('/tournaments/fund', async (req, res, next) => {
  const editDraft = req.session.tournamentEditDraft;
  if (editDraft) return next();
  return requireOrganizerEligibility(req, res, next);
}, async (req, res) => {
  const wantsJson  = req.get('Accept') === 'application/json';
  const editDraft  = req.session.tournamentEditDraft;
  const returnPath = editDraft ? `/tournament/${editDraft.tournamentId}/edit/step2` : '/tournaments/create/step2';

  if (!req.session.tournamentDraft && !editDraft) {
    if (wantsJson) return res.status(400).json({ error: 'No tournament draft in progress.' });
    return res.redirect('/tournaments/create');
  }

  const amountCHL = parseInt(req.body.amountCHL, 10);
  if (!amountCHL || amountCHL <= 0 || amountCHL > 500) {
    if (wantsJson) return res.status(400).json({ error: 'Amount must be between 1 and 500 CHL.' });
    return res.redirect(returnPath);
  }

  const userId = req.currentUser._id;
  const updatedUser = await creditWallet(userId, amountCHL, {
    type:          'top_up',
    source:        'tournament_fund',
    referenceType: 'Tournament',
  });

  if (wantsJson) return res.json({ sbBalance: updatedUser.wallet.purchasedCHL || 0 });
  res.redirect(returnPath);
});

// ── GET /tournaments/create/step3 — Eligibility Criteria ───────────────────
router.get('/tournaments/create/step3', requireOrganizerEligibility, (req, res) => {
  if (!req.session.tournamentDraft?.prizes) return res.redirect('/tournaments/create/step2');
  res.render('app/tournaments/create', {
    title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 3, maxStep: req.session.tournamentDraft.maxStep || 3, errors: [],
    existingCriteria: req.session.tournamentDraft.eligibilityCriteria || [],
  });
});

// ── POST /tournaments/create/step3 ─────────────────────────────────────────
router.post('/tournaments/create/step3', requireOrganizerEligibility, (req, res) => {
  if (!req.session.tournamentDraft?.prizes) return res.redirect('/tournaments/create/step2');
  const maxStep = req.session.tournamentDraft.maxStep || 3;

  if (req.body.intent === 'draft') {
    try {
      const criteria = JSON.parse(req.body.criteria || '[]');
      req.session.tournamentDraft.eligibilityCriteria = Array.isArray(criteria) ? criteria : [];
    } catch {
      req.session.tournamentDraft.eligibilityCriteria = [];
    }
    req.session.tournamentDraft.step = 3;
    return res.redirect('/tournaments?flash=' + encodeURIComponent('Draft saved.'));
  }

  let criteria = [];
  try {
    criteria = JSON.parse(req.body.criteria || '[]');
    if (!Array.isArray(criteria)) throw new Error('not an array');
  } catch {
    return res.render('app/tournaments/create', {
      title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 3, maxStep, errors: ['Invalid eligibility criteria.'],
      existingCriteria: req.session.tournamentDraft.eligibilityCriteria || [],
    });
  }

  const errors = [];
  for (const c of criteria) {
    if (!CRITERIA_FIELDS.includes(c.field)) {
      errors.push(`Invalid criteria field: ${c.field}`);
      continue;
    }
    if (!CRITERIA_OPERATORS.includes(c.operator)) {
      errors.push(`Invalid criteria operator: ${c.operator}`);
      continue;
    }
    if (c.field === 'sex') {
      if (c.operator !== 'eq' || !SEX_VALUES.includes(c.value)) {
        errors.push('Sex criteria must use "eq" with value M, F, or NB.');
      }
    } else if (c.field === 'isFollower') {
      if (c.operator !== 'eq' || c.value !== true) {
        errors.push('Follower criteria must use "eq" with value true.');
      }
    } else if (typeof c.value !== 'number') {
      errors.push(`Value for ${c.field} must be a number.`);
    }
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 3, maxStep, errors, existingCriteria: criteria,
    });
  }

  req.session.tournamentDraft.eligibilityCriteria = criteria;
  req.session.tournamentDraft.maxStep = Math.max(4, maxStep);
  req.session.tournamentDraft.step = 4;
  res.redirect('/tournaments/create/step4');
});

// Resolves stored jury user ids into the {_id, username, displayName} shape the step4 UI expects.
async function loadExistingJury(userIds) {
  if (!userIds || !userIds.length) return [];
  const users = await User.find({ _id: { $in: userIds } }).select('username displayName avatar').lean();
  return users.map(u => ({
    _id:         u._id,
    username:    u.username?.value || '',
    displayName: u.displayName?.value || u.username?.value || '',
    avatar:      u.avatar?.value || null,
  }));
}

// ── GET /tournaments/create/step4 — Jury Selection ─────────────────────────
router.get('/tournaments/create/step4', requireOrganizerEligibility, async (req, res) => {
  if (!req.session.tournamentDraft?.eligibilityCriteria) return res.redirect('/tournaments/create/step3');
  const existingJury = await loadExistingJury(req.session.tournamentDraft.juryUserIds);
  res.render('app/tournaments/create', {
    title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 4, maxStep: req.session.tournamentDraft.maxStep || 4, errors: [], existingJury,
  });
});

// ── POST /tournaments/create/step4 — Jury Selection ────────────────────────
router.post('/tournaments/create/step4', requireOrganizerEligibility, async (req, res) => {
  if (!req.session.tournamentDraft?.eligibilityCriteria) return res.redirect('/tournaments/create/step3');
  const maxStep = req.session.tournamentDraft.maxStep || 4;

  const rawIds = Array.isArray(req.body.juryUserIds) ? req.body.juryUserIds : [req.body.juryUserIds].filter(Boolean);
  const juryUserIds = [...new Set(rawIds)];

  if (req.body.intent === 'draft') {
    req.session.tournamentDraft.juryUserIds = juryUserIds;
    req.session.tournamentDraft.step = 4;
    return res.redirect('/tournaments?flash=' + encodeURIComponent('Draft saved.'));
  }

  const errors = [];
  if (juryUserIds.length < 5 || juryUserIds.length > 7) {
    errors.push('You must select between 5 and 7 jury members.');
  }
  if (juryUserIds.includes(req.currentUser._id.toString())) {
    errors.push('You cannot add yourself as a jury member.');
  }

  let juryUsers = [];
  if (!errors.length) {
    juryUsers = await User.find({
      _id: { $in: juryUserIds },
      accountStatus: { $ne: 'banned' },
      juryBanned: { $ne: true },
    }).select('_id').lean();
    if (juryUsers.length !== juryUserIds.length) {
      errors.push('One or more selected jury members are not eligible.');
    }
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 4, maxStep, errors, existingJury: await loadExistingJury(juryUserIds),
    });
  }

  req.session.tournamentDraft.juryUserIds = juryUserIds;
  req.session.tournamentDraft.step = 5;
  req.session.tournamentDraft.maxStep = Math.max(5, maxStep);
  res.redirect('/tournaments/create/step5');
});

// Builds the render payload shared by the GET and error-path renders of the review step.
async function buildReviewViewData(req, errors) {
  const draft = req.session.tournamentDraft;
  return {
    title: 'Create Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 5, maxStep: draft.maxStep || 5, errors: errors || [],
    formData: draft,
    existingJury: await loadExistingJury(draft.juryUserIds),
  };
}

// ── GET /tournaments/create/step5 — Review ──────────────────────────────────
router.get('/tournaments/create/step5', requireOrganizerEligibility, async (req, res) => {
  const draft = req.session.tournamentDraft;
  if (!draft?.juryUserIds || draft.juryUserIds.length < 5) return res.redirect('/tournaments/create/step4');
  res.render('app/tournaments/create', await buildReviewViewData(req));
});

// ── POST /tournaments/create/step5 — finalize ───────────────────────────────
router.post('/tournaments/create/step5', requireOrganizerEligibility, async (req, res) => {
  const draft = req.session.tournamentDraft;
  if (!draft?.juryUserIds || draft.juryUserIds.length < 5) return res.redirect('/tournaments/create/step4');

  if (req.body.intent === 'draft') {
    return res.redirect('/tournaments?flash=' + encodeURIComponent('Draft saved.'));
  }

  try {
    const tournament = await finalizeTournamentCreation(req);
    delete req.session.tournamentDraft;
    res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('Your tournament is live and accepting candidates.')}`);
  } catch (err) {
    res.render('app/tournaments/create', await buildReviewViewData(req, [err.message || 'Something went wrong creating your tournament.']));
  }
});

async function finalizeTournamentCreation(req) {
  // Required lazily — services/jobs/agenda.js must load after mongoose.connect() resolves in server.js.
  const agenda = require('../services/jobs/agenda');
  const draft  = req.session.tournamentDraft;
  const userId = req.currentUser._id;

  const { groupSize, groupCount } = GROUP_CONFIG[draft.size];
  const openDeadline = new Date(Date.now() + draft.openDays * 24 * 60 * 60 * 1000);
  const totalPrize = draft.prizes.first + draft.prizes.second + draft.prizes.third;

  const updatedUser = await User.findOneAndUpdate(
    { _id: userId, 'wallet.purchasedCHL': { $gte: totalPrize } },
    { $inc: { 'wallet.purchasedCHL': -totalPrize }, $set: { 'wallet.updatedAt': new Date() } },
    { new: true, select: 'wallet' },
  );
  if (!updatedUser) throw new Error('Insufficient balance. Your wallet balance changed.');

  const tournament = await Tournament.create({
    createdBy:   userId,
    name:        draft.name,
    description: draft.description,
    thumbnailUrl: draft.thumbnailUrl || null,
    visibility:  draft.visibility === 'private' ? 'private' : 'public',
    size:        draft.size,
    groupSize,
    groupCount,
    stains: draft.stains || [],
    eligibilityCriteria: draft.eligibilityCriteria,
    wildcardStains: draft.wildcardStains || [],
    prizes: { first: draft.prizes.first, second: draft.prizes.second, third: draft.prizes.third, funded: true },
    status: 'open',
    openDeadline,
  });

  const balanceAfter  = (updatedUser.wallet.purchasedCHL || 0) + (updatedUser.wallet.earnedCHL || 0);
  const balanceBefore = balanceAfter + totalPrize;

  try {
    await Promise.all([
      WalletTransaction.create({
        userId,
        type:          'tournament_prize_hold',
        direction:     'debit',
        amountCHL:     totalPrize,
        amountUSD:     +(totalPrize * EXCHANGE_RATE).toFixed(2),
        exchangeRate:  EXCHANGE_RATE,
        balanceBefore,
        balanceAfter,
        status:        'completed',
        source:        'tournament_creation',
        referenceType: 'Tournament',
        referenceId:   tournament._id,
      }),
      TournamentJury.insertMany(draft.juryUserIds.map(uid => ({ tournamentId: tournament._id, userId: uid, missedVotes: 0, status: 'pending' }))),
      agenda.schedule(openDeadline, 'tournament_open_expiry', { tournamentId: tournament._id.toString() }),
      Notification.insertMany(draft.juryUserIds.map(uid => ({
        userId:  uid,
        type:    'tournament_jury_invite',
        payload: { tournamentId: tournament._id, tournamentName: tournament.name, openDeadline, url: '/tournament/' + tournament._id + '/jury-invite' },
      })), { ordered: false }),
    ]);
  } catch (err) {
    // Undo the wallet debit and remove the half-created tournament so a retry doesn't double-charge
    // or leave an orphaned 'open' tournament behind. Best-effort — don't mask the original error.
    await Promise.all([
      User.findByIdAndUpdate(userId, { $inc: { 'wallet.purchasedCHL': totalPrize } }),
      Tournament.findByIdAndDelete(tournament._id),
      TournamentJury.deleteMany({ tournamentId: tournament._id }),
      Notification.deleteMany({ type: 'tournament_jury_invite', 'payload.tournamentId': tournament._id }),
      agenda.cancel({ name: 'tournament_open_expiry', 'data.tournamentId': tournament._id.toString() }),
    ]).catch(() => {});
    throw err;
  }

  return tournament;
}

// ── Edit flow — reuses the create wizard views, but targets an existing tournament and is
// only reachable by its organizer while status is 'open' or 'cooldown' (not yet live). ──────

// Loads the tournament for an edit request, enforcing organizer + editable-status. Handles its
// own error response and returns null when the request should stop.
async function loadEditableTournament(req, res) {
  if (!mongoose.isValidObjectId(req.params.id)) { res.redirect('/tournaments'); return null; }

  const tournament = await Tournament.findById(req.params.id).lean();
  if (!tournament) { res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser }); return null; }

  if (!tournament.createdBy || tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
    return null;
  }
  if (!['open', 'cooldown'].includes(tournament.status)) {
    res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('This tournament can no longer be edited.')}&flashType=error`);
    return null;
  }

  return tournament;
}

function editDraftFor(req, tournamentId) {
  const draft = req.session.tournamentEditDraft;
  return draft && draft.tournamentId === tournamentId ? draft : null;
}

// Lets the organizer save from any step via the header "Save Changes" button instead of
// walking through the rest of the wizard — safe because the draft is seeded from the live
// tournament, so every step already holds a valid value even if the organizer never visits it.
// Returns true if it handled the response (either saved or re-rendered errors); false means
// the caller should continue with its normal "advance to next step" redirect.
async function trySaveNow(req, res, tournament, renderCurrentStepWithErrors) {
  if (req.body.intent !== 'save') return false;

  try {
    await finalizeTournamentEdit(req, tournament);
    delete req.session.tournamentEditDraft;
    res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('Your changes have been saved.')}`);
  } catch (err) {
    await renderCurrentStepWithErrors([err.message || 'Something went wrong saving your changes.']);
  }
  return true;
}

// ── GET /tournament/:id/edit — seeds the edit draft from the live tournament, then enters
// the wizard at step 1 ──────────────────────────────────────────────────────────────────────
router.get('/tournament/:id/edit', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;

  const jury = await TournamentJury.find({ tournamentId: tournament._id }).select('userId').lean();
  const openDays = Math.max(1, Math.min(3, Math.round((tournament.openDeadline - tournament.createdAt) / (24 * 60 * 60 * 1000))));

  req.session.tournamentEditDraft = {
    tournamentId: tournament._id.toString(),
    name: tournament.name,
    description: tournament.description || '',
    thumbnailUrl: tournament.thumbnailUrl,
    visibility: tournament.visibility,
    stains: tournament.stains || [],
    size: tournament.size,
    openDays,
    prizes: { first: tournament.prizes.first, second: tournament.prizes.second, third: tournament.prizes.third || 0 },
    eligibilityCriteria: tournament.eligibilityCriteria || [],
    wildcardStains: tournament.wildcardStains || [],
    juryUserIds: jury.map(j => j.userId.toString()),
    step: 1,
    maxStep: 5,
  };

  res.redirect(`/tournament/${tournament._id}/edit/step1`);
});

// ── GET /tournament/:id/edit/step1 — Basics ─────────────────────────────────
router.get('/tournament/:id/edit/step1', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 1, maxStep: draft.maxStep || 1, errors: [], formData: draft,
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  });
});

// ── POST /tournament/:id/edit/step1 ─────────────────────────────────────────
router.post('/tournament/:id/edit/step1', upload.tournament.single('thumbnail'), async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const name        = (req.body.name || '').trim();
  const description = (req.body.description || '').trim();
  const size        = parseInt(req.body.size, 10);
  // Open phase length can't be changed once the open phase itself is over (status !== 'open') —
  // the deadline has either passed or is already locked in via the scheduled sweeper job.
  const openDays    = tournament.status === 'open' ? parseInt(req.body.openDays, 10) : draft.openDays;
  const visibility  = req.body.visibility === 'private' ? 'private' : 'public';
  const stains      = normalizeStains(req.body.stains);
  const wildcardStains = normalizeWildcardStains(req.body.wildcardStains);

  const thumbnailUrl = req.file
    ? '/uploads/tournaments/' + req.file.filename
    : req.body.removeThumbnail === '1'
      ? null
      : (draft.thumbnailUrl || null);

  const errors = [];
  if (!thumbnailUrl) errors.push('A tournament thumbnail is required.');
  if (name.length < 3 || name.length > 60) errors.push('Tournament name must be between 3 and 60 characters.');
  if (name && !/^[A-Za-z0-9 ]+$/.test(name)) errors.push('Tournament name may only contain letters, numbers, and spaces.');
  if (![4, 8, 12, 16, 24].includes(size)) errors.push('Participant count must be 4, 8, 12, 16, or 24.');
  if (tournament.status === 'open' && ![1, 2, 3].includes(openDays)) errors.push('Open phase must last 1 to 3 days.');
  if (description.length > 220) errors.push('Description must be 220 characters or fewer.');
  if (name.length >= 3 && name.length <= 60) {
    const existing = await Tournament.findOne({
      _id: { $ne: tournament._id },
      name: { $regex: '^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', $options: 'i' },
    }).select('_id').lean();
    if (existing) errors.push('A tournament with this name already exists.');
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 1, maxStep: draft.maxStep || 1, errors,
      formData: { ...draft, name, description, size: req.body.size, openDays, thumbnailUrl, visibility, stains, wildcardStains },
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
    });
  }

  req.session.tournamentEditDraft = {
    ...draft, name, description, size, openDays, thumbnailUrl, visibility, stains, wildcardStains,
    step: 2, maxStep: Math.max(2, draft.maxStep || 1),
  };

  const handled = await trySaveNow(req, res, tournament, (errors) => res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 1, maxStep: req.session.tournamentEditDraft.maxStep || 1, errors,
    formData: req.session.tournamentEditDraft,
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  }));
  if (handled) return;

  res.redirect(`/tournament/${tournament._id}/edit/step2`);
});

// ── GET /tournament/:id/edit/step2 — Prizes ─────────────────────────────────
router.get('/tournament/:id/edit/step2', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const user     = await User.findById(req.currentUser._id).select('wallet').lean();
  const oldTotal = tournament.prizes.first + tournament.prizes.second + (tournament.prizes.third || 0);

  res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 2, maxStep: draft.maxStep || 2, sbBalance: user?.wallet?.purchasedCHL || 0, errors: [],
    formData: { prizeFirst: draft.prizes.first, prizeSecond: draft.prizes.second, prizeThird: draft.prizes.third },
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status, oldTotal,
  });
});

// ── POST /tournament/:id/edit/step2 ─────────────────────────────────────────
router.post('/tournament/:id/edit/step2', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const prizeFirst  = parseInt(req.body.prizeFirst, 10);
  const prizeSecond = parseInt(req.body.prizeSecond, 10);
  const prizeThird  = parseInt(req.body.prizeThird, 10);

  const errors = [];
  if (!(prizeFirst >= 350))   errors.push('1st place prize must be at least 350 CHL.');
  if (!(prizeSecond >= 100))  errors.push('2nd place prize must be at least 100 CHL.');
  if (!(prizeThird >= 50))    errors.push('3rd place prize must be at least 50 CHL.');
  if (!errors.length) {
    if (!(prizeFirst > prizeSecond)) errors.push('1st place prize must be greater than 2nd place.');
    if (!(prizeSecond > prizeThird)) errors.push('2nd place prize must be greater than 3rd place.');
  }

  const user     = await User.findById(req.currentUser._id).select('wallet').lean();
  const sbBalance = user?.wallet?.purchasedCHL || 0;
  const maxStep   = draft.maxStep || 2;
  const oldTotal  = tournament.prizes.first + tournament.prizes.second + (tournament.prizes.third || 0);

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 2, maxStep, sbBalance, errors, formData: { prizeFirst: req.body.prizeFirst, prizeSecond: req.body.prizeSecond, prizeThird: req.body.prizeThird },
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status, oldTotal,
    });
  }

  const total = prizeFirst + prizeSecond + prizeThird;
  // Only the *increase* over what's already funded needs to be covered by the wallet —
  // the existing prize hold stays put and true-up happens at finalize time.
  const additionalNeeded = Math.max(0, total - oldTotal);

  if (sbBalance >= additionalNeeded) {
    req.session.tournamentEditDraft = {
      ...draft, prizes: { first: prizeFirst, second: prizeSecond, third: prizeThird },
      step: 3, maxStep: Math.max(3, maxStep),
    };

    const handled = await trySaveNow(req, res, tournament, (errs) => res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 2, maxStep: req.session.tournamentEditDraft.maxStep || 2, sbBalance, errors: errs,
      formData: { prizeFirst, prizeSecond, prizeThird },
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status, oldTotal,
    }));
    if (handled) return;

    return res.redirect(`/tournament/${tournament._id}/edit/step3`);
  }

  const shortfall = additionalNeeded - sbBalance;
  res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 2, maxStep, sbBalance, errors: [], formData: { prizeFirst, prizeSecond, prizeThird },
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status, oldTotal,
    insufficientFunds: true, shortfall, total: additionalNeeded,
  });
});

// ── GET /tournament/:id/edit/step3 — Eligibility Criteria ───────────────────
router.get('/tournament/:id/edit/step3', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 3, maxStep: draft.maxStep || 3, errors: [], existingCriteria: draft.eligibilityCriteria || [],
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  });
});

// ── POST /tournament/:id/edit/step3 ─────────────────────────────────────────
router.post('/tournament/:id/edit/step3', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const maxStep = draft.maxStep || 3;

  let criteria = [];
  try {
    criteria = JSON.parse(req.body.criteria || '[]');
    if (!Array.isArray(criteria)) throw new Error('not an array');
  } catch {
    return res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 3, maxStep, errors: ['Invalid eligibility criteria.'], existingCriteria: draft.eligibilityCriteria || [],
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
    });
  }

  const errors = [];
  for (const c of criteria) {
    if (!CRITERIA_FIELDS.includes(c.field)) { errors.push(`Invalid criteria field: ${c.field}`); continue; }
    if (!CRITERIA_OPERATORS.includes(c.operator)) { errors.push(`Invalid criteria operator: ${c.operator}`); continue; }
    if (c.field === 'sex') {
      if (c.operator !== 'eq' || !SEX_VALUES.includes(c.value)) errors.push('Sex criteria must use "eq" with value M, F, or NB.');
    } else if (c.field === 'isFollower') {
      if (c.operator !== 'eq' || c.value !== true) errors.push('Follower criteria must use "eq" with value true.');
    } else if (typeof c.value !== 'number') {
      errors.push(`Value for ${c.field} must be a number.`);
    }
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 3, maxStep, errors, existingCriteria: criteria,
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
    });
  }

  req.session.tournamentEditDraft = { ...draft, eligibilityCriteria: criteria, step: 4, maxStep: Math.max(4, maxStep) };

  const handled = await trySaveNow(req, res, tournament, (errs) => res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 3, maxStep: req.session.tournamentEditDraft.maxStep || 3, errors: errs, existingCriteria: criteria,
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  }));
  if (handled) return;

  res.redirect(`/tournament/${tournament._id}/edit/step4`);
});

// ── GET /tournament/:id/edit/step4 — Jury Selection ─────────────────────────
router.get('/tournament/:id/edit/step4', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const existingJury = await loadExistingJury(draft.juryUserIds);
  res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 4, maxStep: draft.maxStep || 4, errors: [], existingJury,
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  });
});

// ── POST /tournament/:id/edit/step4 ─────────────────────────────────────────
router.post('/tournament/:id/edit/step4', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft) return res.redirect(`/tournament/${req.params.id}/edit`);

  const maxStep = draft.maxStep || 4;
  const rawIds = Array.isArray(req.body.juryUserIds) ? req.body.juryUserIds : [req.body.juryUserIds].filter(Boolean);
  const juryUserIds = [...new Set(rawIds)];

  const errors = [];
  if (juryUserIds.length < 5 || juryUserIds.length > 7) errors.push('You must select between 5 and 7 jury members.');
  if (juryUserIds.includes(req.currentUser._id.toString())) errors.push('You cannot add yourself as a jury member.');

  let juryUsers = [];
  if (!errors.length) {
    juryUsers = await User.find({
      _id: { $in: juryUserIds }, accountStatus: { $ne: 'banned' }, juryBanned: { $ne: true },
    }).select('_id').lean();
    if (juryUsers.length !== juryUserIds.length) errors.push('One or more selected jury members are not eligible.');
  }

  if (errors.length) {
    return res.render('app/tournaments/create', {
      title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
      step: 4, maxStep, errors, existingJury: await loadExistingJury(juryUserIds),
      editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
    });
  }

  req.session.tournamentEditDraft = { ...draft, juryUserIds, step: 5, maxStep: Math.max(5, maxStep) };

  const handled = await trySaveNow(req, res, tournament, async (errs) => res.render('app/tournaments/create', {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 4, maxStep: req.session.tournamentEditDraft.maxStep || 4, errors: errs, existingJury: await loadExistingJury(juryUserIds),
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  }));
  if (handled) return;

  res.redirect(`/tournament/${tournament._id}/edit/step5`);
});

// Builds the render payload shared by the GET and error-path renders of the edit review step.
async function buildEditReviewViewData(req, tournament, errors) {
  const draft = req.session.tournamentEditDraft;
  return {
    title: 'Edit Tournament', activePage: 'tournaments', currentUser: req.currentUser,
    step: 5, maxStep: draft.maxStep || 5, errors: errors || [], formData: draft,
    existingJury: await loadExistingJury(draft.juryUserIds),
    editing: true, tournamentId: tournament._id.toString(), tournamentStatus: tournament.status,
  };
}

// ── GET /tournament/:id/edit/step5 — Review ─────────────────────────────────
router.get('/tournament/:id/edit/step5', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft || !draft.juryUserIds || draft.juryUserIds.length < 5) return res.redirect(`/tournament/${req.params.id}/edit/step4`);

  res.render('app/tournaments/create', await buildEditReviewViewData(req, tournament));
});

// ── POST /tournament/:id/edit/step5 — save changes ──────────────────────────
router.post('/tournament/:id/edit/step5', async (req, res) => {
  const tournament = await loadEditableTournament(req, res);
  if (!tournament) return;
  const draft = editDraftFor(req, req.params.id);
  if (!draft || !draft.juryUserIds || draft.juryUserIds.length < 5) return res.redirect(`/tournament/${req.params.id}/edit/step4`);

  try {
    await finalizeTournamentEdit(req, tournament);
    delete req.session.tournamentEditDraft;
    res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('Your changes have been saved.')}`);
  } catch (err) {
    res.render('app/tournaments/create', await buildEditReviewViewData(req, tournament, [err.message || 'Something went wrong saving your changes.']));
  }
});

async function finalizeTournamentEdit(req, tournament) {
  const agenda = require('../services/jobs/agenda');
  const draft  = req.session.tournamentEditDraft;
  const organizerId = req.currentUser._id;

  // Re-fetch fresh in case status changed mid-edit (e.g. a sweeper job transitioned it while
  // the organizer was still filling out the form).
  const fresh = await Tournament.findOne({ _id: tournament._id, status: { $in: ['open', 'cooldown'] } });
  if (!fresh) throw new Error('This tournament can no longer be edited.');

  // ── Validate everything that can fail *before* making any writes, so a late failure never
  // leaves the tournament partially updated (no multi-document transactions in this codebase). ──

  let groupSize = fresh.groupSize, groupCount = fresh.groupCount;
  if (fresh.size !== draft.size) {
    const approvedCount = await TournamentEntry.countDocuments({ tournamentId: fresh._id, approvalStatus: 'approved' });
    if (approvedCount > draft.size) {
      throw new Error(`Cannot reduce participant count below the ${approvedCount} already-approved candidates.`);
    }
    ({ groupSize, groupCount } = GROUP_CONFIG[draft.size]);
  }

  let openDeadline = fresh.openDeadline;
  let needsReschedule = false;
  if (fresh.status === 'open') {
    const recomputed = new Date(fresh.createdAt.getTime() + draft.openDays * 24 * 60 * 60 * 1000);
    if (recomputed.getTime() !== fresh.openDeadline.getTime()) {
      if (recomputed <= new Date()) throw new Error('That open-phase length would end in the past.');
      openDeadline = recomputed;
      needsReschedule = true;
    }
  }

  const existingJury = await TournamentJury.find({ tournamentId: fresh._id }).lean();
  const existingIds  = new Set(existingJury.map(j => j.userId.toString()));
  const newIds       = new Set(draft.juryUserIds);
  const toAdd        = draft.juryUserIds.filter(id => !existingIds.has(id));
  const toRemove     = existingJury.filter(j => !newIds.has(j.userId.toString()));

  if (toAdd.length) {
    const eligible = await User.find({
      _id: { $in: toAdd }, accountStatus: { $ne: 'banned' }, juryBanned: { $ne: true },
    }).select('_id').lean();
    if (eligible.length !== toAdd.length) throw new Error('One or more selected jury members are not eligible.');
  }

  // ── All validation passed — apply changes ────────────────────────────────

  if (needsReschedule) {
    await agenda.cancel({ name: 'tournament_open_expiry', 'data.tournamentId': fresh._id.toString() });
    await agenda.schedule(openDeadline, 'tournament_open_expiry', { tournamentId: fresh._id.toString() });
  }

  // Prizes / wallet true-up — only the delta over what's already funded moves.
  const oldTotal = fresh.prizes.first + fresh.prizes.second + (fresh.prizes.third || 0);
  const newTotal = draft.prizes.first + draft.prizes.second + draft.prizes.third;
  const delta    = newTotal - oldTotal;

  if (delta > 0) {
    const updatedUser = await User.findOneAndUpdate(
      { _id: organizerId, 'wallet.purchasedCHL': { $gte: delta } },
      { $inc: { 'wallet.purchasedCHL': -delta }, $set: { 'wallet.updatedAt': new Date() } },
      { new: true, select: 'wallet' },
    );
    if (!updatedUser) throw new Error('Insufficient balance. Your wallet balance changed.');

    const balanceAfter  = (updatedUser.wallet.purchasedCHL || 0) + (updatedUser.wallet.earnedCHL || 0);
    const balanceBefore = balanceAfter + delta;
    await WalletTransaction.create({
      userId: organizerId, type: 'tournament_prize_hold', direction: 'debit',
      amountCHL: delta, amountUSD: +(delta * EXCHANGE_RATE).toFixed(2), exchangeRate: EXCHANGE_RATE,
      balanceBefore, balanceAfter, status: 'completed', source: 'tournament_edit',
      referenceType: 'Tournament', referenceId: fresh._id,
    });
  } else if (delta < 0) {
    await creditWallet(organizerId, -delta, {
      type: 'tournament_prize_refund', source: 'tournament_edit', referenceId: fresh._id, referenceType: 'Tournament',
    });
  }

  // Eligibility criteria — re-check already-submitted candidates, drop anyone who no longer qualifies.
  const criteriaChanged = JSON.stringify(fresh.eligibilityCriteria || []) !== JSON.stringify(draft.eligibilityCriteria || []);
  if (criteriaChanged) {
    const affectedEntries = await TournamentEntry.find({
      tournamentId: fresh._id, approvalStatus: { $in: ['pending', 'approved'] },
    }).lean();

    for (const entry of affectedEntries) {
      const stillMeets = await estimateParticipantPool.meetsTournamentCriteria(
        entry.userId, entry.entryId, organizerId, draft.eligibilityCriteria,
      );
      if (!stillMeets) {
        await TournamentEntry.updateOne({ _id: entry._id }, { $set: { approvalStatus: 'rejected', reviewedAt: new Date() } });
        await Notification.create({
          userId:  entry.userId,
          type:    'tournament_entry_removed',
          payload: { tournamentId: fresh._id, tournamentName: draft.name, url: '/tournament/' + fresh._id },
        });
      }
    }
  }

  // Jury — apply the diff computed above.
  if (toAdd.length) {
    await TournamentJury.insertMany(toAdd.map(uid => ({ tournamentId: fresh._id, userId: uid, missedVotes: 0, status: 'pending' })));
    await Notification.insertMany(toAdd.map(uid => ({
      userId:  uid,
      type:    'tournament_jury_invite',
      payload: { tournamentId: fresh._id, tournamentName: draft.name, openDeadline, url: '/tournament/' + fresh._id + '/jury-invite' },
    })), { ordered: false });
  }
  if (toRemove.length) {
    await TournamentJury.deleteMany({ _id: { $in: toRemove.map(j => j._id) } });
  }

  // Persist basics last, once every other subsystem has already succeeded.
  await Tournament.updateOne({ _id: fresh._id }, { $set: {
    name: draft.name, description: draft.description, thumbnailUrl: draft.thumbnailUrl,
    visibility: draft.visibility, size: draft.size, groupSize, groupCount, stains: draft.stains || [],
    eligibilityCriteria: draft.eligibilityCriteria, wildcardStains: draft.wildcardStains || [], openDeadline,
    'prizes.first': draft.prizes.first, 'prizes.second': draft.prizes.second, 'prizes.third': draft.prizes.third,
  } });
}

// Shared sort options + aggregation pipeline for browsing a tournament's TournamentEntry docs
// (used by both the detail page's Entries row and the organizer's dedicated review queue) —
// joins in the Entry, User, and follower-count data needed to sort/search by rating, rating
// count, recency, or follower count.
const TOURNAMENT_ENTRY_SORTS = {
  recent:      { submittedAt: -1 },
  oldest:      { submittedAt: 1 },
  rating:      { 'entry.ratingAvg': -1 },
  ratingCount: { 'entry.ratingCount': -1 },
  followers:   { followerCount: -1 },
};

function buildTournamentEntryPipeline(tournamentId, approvalStatus, sort, search) {
  const pipeline = [
    { $match: { tournamentId, approvalStatus } },
    { $lookup: { from: 'entries', localField: 'entryId', foreignField: '_id', as: 'entry' } },
    { $unwind: '$entry' },
    { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user' } },
    { $unwind: '$user' },
  ];

  if (search) {
    pipeline.push({ $match: {
      'user.username.value': { $regex: search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' },
    } });
  }

  pipeline.push(
    { $lookup: {
        from: 'follows', localField: 'userId', foreignField: 'followingId', as: 'followerDocs',
        pipeline: [{ $project: { _id: 1 } }],
    } },
    { $addFields: { followerCount: { $size: '$followerDocs' } } },
    { $sort: TOURNAMENT_ENTRY_SORTS[sort] },
    { $project: {
        approvalStatus: 1, submittedAt: 1, followerCount: 1, autoSubmitted: 1,
        entryId: { _id: '$entry._id', title: '$entry.title', caption: '$entry.caption', mediaType: '$entry.mediaType', mediaUrl: '$entry.mediaUrl', ratingAvg: '$entry.ratingAvg', ratingCount: '$entry.ratingCount', takeOnCount: '$entry.takeOnCount', tags: '$entry.tags' },
        userId:  { _id: '$user._id', username: '$user.username', displayName: '$user.displayName', avatar: '$user.avatar' },
    } },
  );

  return pipeline;
}

// ── GET /tournament/:id — detail ───────────────────────────────────────────
router.get('/tournament/:id', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.redirect('/tournaments');

  const tournament = await Tournament.findById(req.params.id).populate('createdBy', 'username displayName avatar').lean();
  if (!tournament || tournament.status === 'canceled') {
    return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const isOrganizer = !!tournament.createdBy && tournament.createdBy._id.toString() === req.currentUser._id.toString();

  Tournament.updateOne({ _id: tournament._id }, { $inc: { viewCount: 1 } }).catch(() => {});

  const [groups, entries, matches, userEntry, pendingCount, declinedJuryCount, isFollowing, isLoopedIn, isJuror] = await Promise.all([
    TournamentGroup.find({ tournamentId: tournament._id })
      .populate({ path: 'memberIds', populate: [
        { path: 'userId', select: 'username displayName avatar' },
        { path: 'entryId' },
      ] })
      .lean(),
    TournamentEntry.find({
      tournamentId: tournament._id,
      approvalStatus: { $in: ['approved', 'pending'] },
    })
      .populate('entryId')
      .populate('userId', 'username displayName avatar')
      .lean(),
    TournamentMatch.find({ tournamentId: tournament._id })
      .populate({ path: 'tournamentEntryIdA', populate: [
        { path: 'userId', select: 'username displayName avatar' },
        { path: 'entryId' },
      ] })
      .populate({ path: 'tournamentEntryIdB', populate: [
        { path: 'userId', select: 'username displayName avatar' },
        { path: 'entryId' },
      ] })
      .populate('contestId')
      .lean(),
    TournamentEntry.findOne({ tournamentId: tournament._id, userId: req.currentUser._id }).populate('entryId').lean(),
    isOrganizer && (tournament.status === 'open' || tournament.status === 'cooldown')
      ? TournamentEntry.countDocuments({ tournamentId: tournament._id, approvalStatus: 'pending' })
      : 0,
    isOrganizer
      ? TournamentJury.countDocuments({ tournamentId: tournament._id, status: 'declined' })
      : 0,
    !isOrganizer && tournament.createdBy
      ? Follow.exists({ followerId: req.currentUser._id, followingId: tournament.createdBy._id })
      : false,
    !isOrganizer
      ? TournamentLoop.exists({ tournamentId: tournament._id, userId: req.currentUser._id })
      : false,
    !isOrganizer
      ? TournamentJury.exists({ tournamentId: tournament._id, userId: req.currentUser._id })
      : false,
  ]);

  // Live group standings: mirror resolveGroup's tiebreak cascade (services/jobs/tournamentJobs.js) so the
  // displayed order matches how advancement is actually decided. Members that already have a
  // stored groupRank (their group finished and they advanced) keep that officially-resolved
  // order; everyone else falls back to a live recompute from groupPoints/ratingAvg/ratingCount/
  // totalVotesInGroup — the same fields resolveGroup itself sorts on before a group completes.
  const closedGroupContestIds = matches
    .filter(m => m.stage === 'group' && m.status === 'closed' && !m.isTiebreakerMatch)
    .map(m => m.contestId?._id || m.contestId)
    .filter(Boolean);
  const groupVoteAgg = closedGroupContestIds.length
    ? await ContestVote.aggregate([
        { $match: { contestId: { $in: closedGroupContestIds } } },
        { $group: { _id: '$entryId', count: { $sum: 1 } } },
      ])
    : [];
  const votesByEntryId = {};
  groupVoteAgg.forEach(row => { votesByEntryId[row._id.toString()] = row.count; });

  groups.forEach(g => {
    g.memberIds = (g.memberIds || []).slice().sort((a, b) => {
      const rankA = a.groupRank || Infinity;
      const rankB = b.groupRank || Infinity;
      if (rankA !== rankB) return rankA - rankB;
      const votesA = votesByEntryId[a.entryId?._id?.toString()] || 0;
      const votesB = votesByEntryId[b.entryId?._id?.toString()] || 0;
      return (b.groupPoints || 0) - (a.groupPoints || 0) ||
             (b.entryId?.ratingAvg || 0) - (a.entryId?.ratingAvg || 0) ||
             (b.entryId?.ratingCount || 0) - (a.entryId?.ratingCount || 0) ||
             votesB - votesA;
    });
  });

  const entryOwnerIds = [...new Set(
    entries.map(e => e.userId?._id?.toString()).filter(id => id && id !== req.currentUser._id.toString()),
  )];

  const [comments, placements, entryFollowDocs, entryLoopDocs] = await Promise.all([
    loadTournamentComments(tournament._id),
    tournament.status === 'closed' ? loadTournamentPlacements(tournament._id) : {},
    entryOwnerIds.length
      ? Follow.find({ followerId: req.currentUser._id, followingId: { $in: entryOwnerIds } }).select('followingId').lean()
      : [],
    entries.length
      ? TournamentEntryLoop.find({ tournamentEntryId: { $in: entries.map(e => e._id) }, userId: req.currentUser._id }).select('tournamentEntryId').lean()
      : [],
  ]);
  const entryFollowingSet = new Set(entryFollowDocs.map(f => f.followingId.toString()));
  const entryLoopedInSet  = new Set(entryLoopDocs.map(w => w.tournamentEntryId.toString()));

  res.render('app/tournaments/detail', {
    title:      tournament.name,
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, groups, entries, matches, userEntry, isOrganizer, pendingCount, declinedJuryCount,
    entryLoopedInSet,
    entryFollowingSet,
    isFollowing: !!isFollowing,
    isLoopedIn: !!isLoopedIn,
    isJuror: !!isJuror,
    comments,
    placements,
    flash: req.query.flash || null,
    flashType: req.query.flashType === 'error' ? 'error' : 'success',
  });
});

// Derives 1st/2nd/3rd place TournamentEntry docs (with populated userId) from the Final and
// 3rd-place knockout matches — no separate "placement" field is persisted anywhere; the winner
// of each match already tells us who placed where.
async function loadTournamentPlacements(tournamentId) {
  const [finalMatch, thirdMatch] = await Promise.all([
    TournamentMatch.findOne({ tournamentId, knockoutRound: 'Final' }).lean(),
    TournamentMatch.findOne({ tournamentId, knockoutRound: '3rd' }).lean(),
  ]);

  function winnerTournamentEntryId(match) {
    if (!match || !match.winnerId) return null;
    return match.entryIdA.toString() === match.winnerId.toString() ? match.tournamentEntryIdA : match.tournamentEntryIdB;
  }
  function loserTournamentEntryId(match) {
    if (!match || !match.winnerId) return null;
    return match.entryIdA.toString() === match.winnerId.toString() ? match.tournamentEntryIdB : match.tournamentEntryIdA;
  }

  const placementIds = {
    first:  winnerTournamentEntryId(finalMatch),
    second: loserTournamentEntryId(finalMatch),
    third:  winnerTournamentEntryId(thirdMatch),
  };

  const ids = Object.values(placementIds).filter(Boolean);
  if (!ids.length) return {};

  const entries = await TournamentEntry.find({ _id: { $in: ids } })
    .populate('userId', 'username displayName avatar')
    .lean();
  const byId = {};
  entries.forEach(e => { byId[e._id.toString()] = e; });

  return {
    first:  placementIds.first  ? byId[placementIds.first.toString()]  || null : null,
    second: placementIds.second ? byId[placementIds.second.toString()] || null : null,
    third:  placementIds.third  ? byId[placementIds.third.toString()]  || null : null,
  };
}

// Loads top-level tournament comments + their replies, sorted by a recency-weighted net-reaction score.
async function loadTournamentComments(tournamentId) {
  const topLevelComments = await TournamentComment.find({ tournamentId, parentId: null, hidden: false })
    .populate('userId', 'username displayName avatar')
    .sort({ createdAt: -1 })
    .lean()
    .catch(() => []);

  const topLevelIds = topLevelComments.map(c => c._id);
  const allReplies = topLevelIds.length
    ? await TournamentComment.find({ parentId: { $in: topLevelIds }, hidden: false })
        .populate('userId', 'username displayName avatar')
        .sort({ createdAt: 1 })
        .lean()
        .catch(() => [])
    : [];

  const replyMap = {};
  for (const r of allReplies) {
    const pid = r.parentId.toString();
    if (!replyMap[pid]) replyMap[pid] = [];
    replyMap[pid].push(r);
  }
  const comments = topLevelComments.map(c => ({ ...c, replies: replyMap[c._id.toString()] || [] }));

  const now = Date.now();
  const score = c => {
    const ownNet   = (c.likes?.length || 0) - (c.dislikes?.length || 0);
    const hoursOld = (now - new Date(c.createdAt).getTime()) / 3600000;
    const recency  = 1 / Math.pow(hoursOld + 2, 1.5);
    const replyBoost = (c.replies || []).reduce((sum, r) => {
      const rNet   = (r.likes?.length || 0) - (r.dislikes?.length || 0);
      const rHours = (now - new Date(r.createdAt).getTime()) / 3600000;
      return sum + rNet * (1 / Math.pow(rHours + 2, 1.5));
    }, 0);
    return ownNet + replyBoost * 0.25 + recency;
  };
  comments.sort((a, b) => score(b) - score(a));

  return comments;
}

// ── POST /tournament/:id/cancel — organizer self-cancel ─────────────────────
router.post('/tournament/:id/cancel', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Not found.' });

  const tournament = await Tournament.findOne({ _id: req.params.id, status: { $in: ['open', 'cooldown'] } }).lean();
  if (!tournament) return res.status(404).json({ error: 'This tournament can no longer be canceled.' });
  if (tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).json({ error: 'Only the organizer can cancel this tournament.' });
  }

  const agenda = require('../services/jobs/agenda');
  await Promise.all([
    agenda.cancel({ name: 'tournament_open_expiry', 'data.tournamentId': tournament._id.toString() }),
    agenda.cancel({ name: 'tournament_cooldown_expiry', 'data.tournamentId': tournament._id.toString() }),
  ]);
  await cancelTournament(tournament._id, 'organizer_canceled');

  res.json({ success: true });
});

// ── POST /tournament/:id/entry/withdraw — candidate withdraws their own submission ──
// Only allowed while the organizer hasn't reviewed it yet — once approved/rejected the
// entry is locked into (or out of) the bracket and can no longer be pulled by the candidate.
router.post('/tournament/:id/entry/withdraw', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });

  const entry = await TournamentEntry.findOne({ tournamentId: req.params.id, userId: req.currentUser._id });
  if (!entry) return res.status(404).json({ error: 'Submission not found.' });
  if (entry.approvalStatus !== 'pending') {
    return res.status(400).json({ error: 'Your entry has already been reviewed and can no longer be withdrawn.' });
  }

  await entry.deleteOne();
  res.json({ success: true });
});

// ── POST /tournament/:id/loop-in — toggle loop-in/subscribe ─────────────────
router.post('/tournament/:id/loop-in', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });

  const existing = await TournamentLoop.findOne({ tournamentId: req.params.id, userId: req.currentUser._id });
  if (existing) {
    await existing.deleteOne();
    return res.json({ loopedIn: false });
  }

  const tournament = await Tournament.findById(req.params.id).select('createdBy').lean();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found.' });
  if (tournament.createdBy.toString() === req.currentUser._id.toString()) {
    return res.status(400).json({ error: "You can't loop in on your own tournament." });
  }

  await TournamentLoop.create({ tournamentId: req.params.id, userId: req.currentUser._id });
  res.json({ loopedIn: true });
});

// ── POST /tournament/:id/entry/:teId/loop-in — toggle loop-in on a specific candidate ───
router.post('/tournament/:id/entry/:teId/loop-in', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.teId)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }

  const existing = await TournamentEntryLoop.findOne({ tournamentEntryId: req.params.teId, userId: req.currentUser._id });
  if (existing) {
    await existing.deleteOne();
    return res.json({ loopedIn: false });
  }

  const entry = await TournamentEntry.findById(req.params.teId).select('tournamentId userId').lean();
  if (!entry) return res.status(404).json({ error: 'Entry not found.' });
  if (entry.tournamentId.toString() !== req.params.id) {
    return res.status(400).json({ error: 'Entry does not belong to this tournament.' });
  }
  if (entry.userId.toString() === req.currentUser._id.toString()) {
    return res.status(400).json({ error: "You can't loop in on your own entry." });
  }

  await TournamentEntryLoop.create({ tournamentEntryId: req.params.teId, tournamentId: req.params.id, userId: req.currentUser._id });
  res.json({ loopedIn: true });
});

// ── POST /tournament/:id/report — report the tournament itself ──────────────
router.post('/tournament/:id/report', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });

  const tournament = await Tournament.findById(req.params.id).select('createdBy').lean();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found.' });
  if (tournament.createdBy.toString() === req.currentUser._id.toString()) {
    return res.status(400).json({ error: "You can't report your own tournament." });
  }

  try {
    await TournamentReport.create({ tournamentId: req.params.id, reportedBy: req.currentUser._id });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: "You've already reported this tournament." });
    console.error('Tournament report error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

// ── Tournament comments ──────────────────────────────────────────────────────

router.post('/tournament/:id/comments', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });

  const body = req.body.body?.trim();
  if (!body || body.length === 0) return res.status(400).json({ error: 'Comment body is required.' });
  if (body.replace(/\s/g, '').length > 280) return res.status(400).json({ error: 'Comment cannot exceed 280 characters (spaces not counted).' });

  const parentId = req.body.parentId || null;
  if (parentId && !mongoose.isValidObjectId(parentId)) return res.status(400).json({ error: 'Invalid parentId.' });

  const tournament = await Tournament.findById(req.params.id).select('_id').lean();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found.' });

  let effectiveParentId = null;
  if (parentId) {
    const parent = await TournamentComment.findById(parentId).select('tournamentId parentId').lean().catch(() => null);
    if (!parent || parent.tournamentId.toString() !== req.params.id) {
      return res.status(400).json({ error: 'Invalid parent comment.' });
    }
    effectiveParentId = parent.parentId || parent._id;
  }

  try {
    const comment = await TournamentComment.create({
      tournamentId: tournament._id,
      userId:       req.currentUser._id,
      parentId:     effectiveParentId,
      body,
    });

    res.json({
      _id:          comment._id,
      tournamentId: comment.tournamentId,
      userId:       comment.userId,
      parentId:     comment.parentId,
      body:         comment.body,
      editedAt:     comment.editedAt,
      createdAt:    comment.createdAt,
      user: {
        username:    req.currentUser.username,
        displayName: req.currentUser.displayName || null,
        avatar:      req.currentUser.avatar || null,
      },
    });
  } catch (err) {
    console.error('Tournament comment create error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

router.patch('/tournament/:id/comments/:cid', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.cid)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }

  const body = req.body.body?.trim();
  if (!body || body.length === 0) return res.status(400).json({ error: 'Comment body is required.' });
  if (body.replace(/\s/g, '').length > 280) return res.status(400).json({ error: 'Comment cannot exceed 280 characters (spaces not counted).' });

  const comment = await TournamentComment.findById(req.params.cid).catch(() => null);
  if (!comment || comment.tournamentId.toString() !== req.params.id) {
    return res.status(404).json({ error: 'Comment not found.' });
  }
  if (comment.userId.toString() !== req.currentUser._id.toString()) {
    return res.status(403).json({ error: 'Not your comment.' });
  }

  comment.body     = body;
  comment.editedAt = new Date();
  await comment.save();

  res.json({ ok: true, body: comment.body, editedAt: comment.editedAt });
});

router.delete('/tournament/:id/comments/:cid', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.cid)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }

  const comment = await TournamentComment.findById(req.params.cid).catch(() => null);
  if (!comment || comment.tournamentId.toString() !== req.params.id) {
    return res.status(404).json({ error: 'Comment not found.' });
  }

  const MOD_ROLES = new Set(['moderator', 'supervisor', 'superadmin', 'founder']);
  const isOwn = comment.userId.toString() === req.currentUser._id.toString();
  const isMod = MOD_ROLES.has(req.currentUser.role);
  if (!isOwn && !isMod) return res.status(403).json({ error: 'Not authorized.' });

  await Promise.all([
    TournamentComment.deleteOne({ _id: comment._id }),
    TournamentComment.deleteMany({ parentId: comment._id }),
    TournamentCommentReport.deleteMany({ tournamentCommentId: comment._id }),
  ]);

  res.json({ ok: true });
});

router.post('/tournament/:id/comments/:cid/report', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.cid)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }

  const comment = await TournamentComment.findById(req.params.cid).select('userId tournamentId').lean().catch(() => null);
  if (!comment || comment.tournamentId.toString() !== req.params.id) {
    return res.status(404).json({ error: 'Comment not found.' });
  }
  if (comment.userId.toString() === req.currentUser._id.toString()) {
    return res.status(400).json({ error: "You can't report your own comment." });
  }

  const existing = await TournamentCommentReport.findOne({ tournamentCommentId: comment._id, reportedBy: req.currentUser._id }).lean();
  if (existing) {
    if (existing.status !== 'rejected') return res.status(409).json({ error: "You've already reported this comment." });
    await TournamentCommentReport.updateOne({ _id: existing._id }, { $set: { status: 'pending' } });
    await TournamentComment.updateOne({ _id: comment._id }, { $set: { hidden: true } });
    return res.json({ ok: true });
  }

  try {
    await TournamentCommentReport.create({ tournamentCommentId: comment._id, reportedBy: req.currentUser._id });
    await TournamentComment.updateOne({ _id: comment._id }, { $set: { hidden: true } });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: "You've already reported this comment." });
    console.error('Tournament comment report error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

router.post('/tournament/:id/comments/:cid/react', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.cid)) {
    return res.status(400).json({ error: 'Invalid ID.' });
  }
  const { type } = req.body;
  if (!['like', 'dislike'].includes(type)) return res.status(400).json({ error: 'Invalid type.' });

  const comment = await TournamentComment.findById(req.params.cid).select('tournamentId likes dislikes').catch(() => null);
  if (!comment || comment.tournamentId.toString() !== req.params.id) return res.status(404).json({ error: 'Comment not found.' });

  const uid = req.currentUser._id.toString();
  const hasLiked    = comment.likes.some(id => id.toString() === uid);
  const hasDisliked = comment.dislikes.some(id => id.toString() === uid);
  let update;
  if (type === 'like') {
    if (hasLiked)         update = { $pull: { likes: req.currentUser._id } };
    else if (hasDisliked) update = { $pull: { dislikes: req.currentUser._id }, $addToSet: { likes: req.currentUser._id } };
    else                  update = { $addToSet: { likes: req.currentUser._id } };
  } else {
    if (hasDisliked)   update = { $pull: { dislikes: req.currentUser._id } };
    else if (hasLiked) update = { $pull: { likes: req.currentUser._id }, $addToSet: { dislikes: req.currentUser._id } };
    else               update = { $addToSet: { dislikes: req.currentUser._id } };
  }
  const updated = await TournamentComment.findByIdAndUpdate(comment._id, update, { new: true }).select('likes dislikes');
  const userLiked    = updated.likes.some(id => id.toString() === uid);
  const userDisliked = updated.dislikes.some(id => id.toString() === uid);
  res.json({ likes: updated.likes.length, dislikes: updated.dislikes.length, userLiked, userDisliked });
});

// ── GET /tournament/:id/review — organizer candidate review ────────────────
router.get('/tournament/:id/review', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.redirect('/tournaments');

  const tournament = await Tournament.findById(req.params.id).lean();
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (!tournament.createdBy || tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const sort   = TOURNAMENT_ENTRY_SORTS[req.query.sort] ? req.query.sort : 'recent';
  const search = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';

  const pendingEntries = await TournamentEntry.aggregate(
    buildTournamentEntryPipeline(tournament._id, 'pending', sort, search),
  );

  const candidateUserIds = [...new Set(pendingEntries.map(pe => pe.userId?._id?.toString()).filter(Boolean))];
  const [followingDocs, nominationCounts] = await Promise.all([
    candidateUserIds.length
      ? Follow.find({ followerId: req.currentUser._id, followingId: { $in: candidateUserIds } }).select('followingId').lean()
      : [],
    candidateUserIds.length
      ? Nomination.aggregate([
          { $match: { nomineeId: { $in: candidateUserIds.map(id => new mongoose.Types.ObjectId(id)) }, status: 'accepted' } },
          { $group: { _id: '$nomineeId', count: { $sum: 1 } } },
        ])
      : [],
  ]);
  const followingSet = new Set(followingDocs.map(f => f.followingId.toString()));
  const nominationCountMap = {};
  nominationCounts.forEach(nc => { nominationCountMap[nc._id.toString()] = nc.count; });

  res.render('app/tournaments/review', {
    title:      'Review Candidates',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, pendingEntries, sort, search: req.query.q || '',
    followingSet, nominationCountMap,
  });
});

// ── GET /tournament/:id/jury-vote/:matchId — juror tie-break vote page ─────
router.get('/tournament/:id/jury-vote/:matchId', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.matchId)) {
    return res.redirect('/tournaments');
  }

  const [tournament, jurorRecord] = await Promise.all([
    Tournament.findById(req.params.id).lean(),
    TournamentJury.findOne({ tournamentId: req.params.id, userId: req.currentUser._id, status: 'accepted' }).lean(),
  ]);
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (!jurorRecord) return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });

  const match = await TournamentMatch.findOne({ _id: req.params.matchId, tournamentId: tournament._id }).lean();
  if (!match || match.status !== 'tie' || match.tieStatus !== 'jury_pending') {
    return res.redirect(`/tournament/${tournament._id}`);
  }

  const existingVote = await TournamentJuryVote.findOne({ matchId: match._id, jurorId: req.currentUser._id }).lean();
  if (existingVote) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('You already voted on this tie.')}`);
  }

  const Entry = require('../models/Entry');
  const [entryA, entryB] = await Promise.all([
    Entry.findById(match.entryIdA).lean(),
    Entry.findById(match.entryIdB).lean(),
  ]);
  // A contestant can have deleted their account mid-tournament, taking their Entry with it.
  if (!entryA || !entryB) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('One of the entries in this match is no longer available.')}`);
  }

  res.render('app/tournaments/jury-vote', {
    title:      'Jury Tie-Break',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, match, entryA, entryB,
  });
});

// ── GET /tournament/:id/organizer-vote/:matchId — organizer tie-break vote page ────
// Reached only after the 6h jury window expired without quorum (TournamentMatch.tieStatus
// flips to 'organizer_pending' — see services/jobs/tournamentJobs.js's tournament_jury_expiry job).
router.get('/tournament/:id/organizer-vote/:matchId', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.matchId)) {
    return res.redirect('/tournaments');
  }

  const tournament = await Tournament.findById(req.params.id).lean();
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const match = await TournamentMatch.findOne({ _id: req.params.matchId, tournamentId: tournament._id }).lean();
  if (!match || match.tieStatus !== 'organizer_pending') {
    return res.redirect(`/tournament/${tournament._id}`);
  }

  const Entry = require('../models/Entry');
  const [entryA, entryB] = await Promise.all([
    Entry.findById(match.entryIdA).lean(),
    Entry.findById(match.entryIdB).lean(),
  ]);
  // A contestant can have deleted their account mid-tournament, taking their Entry with it.
  if (!entryA || !entryB) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('One of the entries in this match is no longer available.')}`);
  }

  res.render('app/tournaments/organizer-vote', {
    title:      'Break the Tie',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, match, entryA, entryB,
  });
});

// ── GET /tournament/:id/group-jury-vote/:groupId — juror vote page for a 3+-way ──
// group-ranking boundary tie (distinct from the match-tie jury-vote page above).
router.get('/tournament/:id/group-jury-vote/:groupId', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.groupId)) {
    return res.redirect('/tournaments');
  }

  const [tournament, jurorRecord] = await Promise.all([
    Tournament.findById(req.params.id).lean(),
    TournamentJury.findOne({ tournamentId: req.params.id, userId: req.currentUser._id, status: 'accepted' }).lean(),
  ]);
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (!jurorRecord) return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });

  const group = await TournamentGroup.findOne({ _id: req.params.groupId, tournamentId: tournament._id }).lean();
  if (!group || group.tieStatus !== 'jury_pending') {
    return res.redirect(`/tournament/${tournament._id}`);
  }

  const existingVote = await TournamentGroupTieVote.findOne({ groupId: group._id, jurorId: req.currentUser._id }).lean();
  if (existingVote) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('You already voted on this tie.')}`);
  }

  const tiedEntries = await TournamentEntry.find({ _id: { $in: group.tiedEntryIds } })
    .populate('entryId', 'mediaUrl mediaType')
    .lean();
  if (tiedEntries.length !== group.tiedEntryIds.length) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('One of the entries in this tie is no longer available.')}`);
  }
  // Keep the on-screen order stable across reloads and match tiedEntryIds's stored order.
  const byId = {};
  tiedEntries.forEach(te => { byId[te._id.toString()] = te; });
  const orderedEntries = group.tiedEntryIds.map(id => byId[id.toString()]);

  res.render('app/tournaments/group-jury-vote', {
    title:      'Jury Tie-Break',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, group, tiedEntries: orderedEntries,
  });
});

// ── GET /tournament/:id/group-organizer-vote/:groupId — organizer tie-break page for a
// 3+-way group-ranking boundary tie the jury couldn't resolve within its 6h window ──────
router.get('/tournament/:id/group-organizer-vote/:groupId', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.groupId)) {
    return res.redirect('/tournaments');
  }

  const tournament = await Tournament.findById(req.params.id).lean();
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const group = await TournamentGroup.findOne({ _id: req.params.groupId, tournamentId: tournament._id }).lean();
  if (!group || group.tieStatus !== 'organizer_pending') {
    return res.redirect(`/tournament/${tournament._id}`);
  }

  const tiedEntries = await TournamentEntry.find({ _id: { $in: group.tiedEntryIds } })
    .populate('entryId', 'mediaUrl mediaType')
    .lean();
  if (tiedEntries.length !== group.tiedEntryIds.length) {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('One of the entries in this tie is no longer available.')}`);
  }
  const byId = {};
  tiedEntries.forEach(te => { byId[te._id.toString()] = te; });
  const orderedEntries = group.tiedEntryIds.map(id => byId[id.toString()]);

  res.render('app/tournaments/group-organizer-vote', {
    title:      'Break the Tie',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, group, tiedEntries: orderedEntries,
  });
});

// ── GET /tournament/:id/jury-invite — juror accept/decline page ────────────
router.get('/tournament/:id/jury-invite', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.redirect('/tournaments');

  const [tournament, jurorRecord] = await Promise.all([
    Tournament.findById(req.params.id).lean(),
    TournamentJury.findOne({ tournamentId: req.params.id, userId: req.currentUser._id }).lean(),
  ]);
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (!jurorRecord) return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });

  if (tournament.status !== 'open') {
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent('This jury invite is no longer active.')}`);
  }
  if (jurorRecord.status !== 'pending') {
    const msg = jurorRecord.status === 'accepted' ? 'You already accepted this jury invite.' : 'You already declined this jury invite.';
    return res.redirect(`/tournament/${tournament._id}?flash=${encodeURIComponent(msg)}`);
  }

  res.render('app/tournaments/jury-invite', {
    title:      'Jury Invitation',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament,
  });
});

// ── POST /tournament/:id/jury-invite/respond — accept or decline ───────────
router.post('/tournament/:id/jury-invite/respond', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid tournament.' });

  const action = req.body.action;
  if (action !== 'accept' && action !== 'decline') return res.status(400).json({ error: 'Invalid action.' });

  const tournament = await Tournament.findOne({ _id: req.params.id, status: 'open' }).lean();
  if (!tournament) return res.status(400).json({ error: 'This jury invite is no longer active.' });

  const jurorRecord = await TournamentJury.findOneAndUpdate(
    { tournamentId: tournament._id, userId: req.currentUser._id, status: 'pending' },
    { $set: { status: action === 'accept' ? 'accepted' : 'declined', respondedAt: new Date() } },
  );
  if (!jurorRecord) return res.status(400).json({ error: 'You already responded to this invite.' });

  if (action === 'decline') {
    await Notification.create({
      userId:  tournament.createdBy,
      type:    'tournament_jury_declined',
      payload: { tournamentId: tournament._id, tournamentName: tournament.name, url: '/tournament/' + tournament._id + '/jury/manage' },
    });
  }

  res.json({ success: true, redirect: `/tournament/${tournament._id}` });
});

// ── GET /tournament/:id/jury/manage — organizer: view jury + replace declines ──
router.get('/tournament/:id/jury/manage', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.redirect('/tournaments');

  const tournament = await Tournament.findById(req.params.id).lean();
  if (!tournament) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  if (!tournament.createdBy || tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const jury = await TournamentJury.find({ tournamentId: tournament._id })
    .populate('userId', 'username displayName avatar')
    .lean();

  res.render('app/tournaments/jury-manage', {
    title:      'Manage Jury',
    activePage: 'tournaments',
    currentUser: req.currentUser,
    tournament, jury,
  });
});

// ── POST /tournament/:id/jury/replace — organizer: swap a declined juror ───
router.post('/tournament/:id/jury/replace', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid tournament.' });

  const { oldUserId, newUserId } = req.body;
  if (!mongoose.isValidObjectId(oldUserId) || !mongoose.isValidObjectId(newUserId)) {
    return res.status(400).json({ error: 'Invalid user.' });
  }

  const tournament = await Tournament.findOne({ _id: req.params.id, status: 'open' }).lean();
  if (!tournament) return res.status(400).json({ error: 'This tournament is no longer accepting jury changes.' });
  if (tournament.createdBy.toString() !== req.currentUser._id.toString()) {
    return res.status(403).json({ error: 'Not authorized.' });
  }

  if (newUserId === tournament.createdBy.toString()) {
    return res.status(400).json({ error: 'The organizer cannot serve as jury.' });
  }

  const [alreadyJury, newUser] = await Promise.all([
    TournamentJury.findOne({ tournamentId: tournament._id, userId: newUserId }),
    User.findOne({ _id: newUserId, role: 'user', accountStatus: { $ne: 'banned' }, juryBanned: { $ne: true } }).select('_id').lean(),
  ]);

  if (alreadyJury) return res.status(400).json({ error: 'That user is already on this tournament\'s jury.' });
  if (!newUser) return res.status(400).json({ error: 'That user is not eligible to serve as jury.' });

  // Atomic find-and-delete: only one concurrent replace request can consume this declined
  // slot, so two racing requests can't both succeed and grow the jury past its intended size.
  const oldRecord = await TournamentJury.findOneAndDelete({ tournamentId: tournament._id, userId: oldUserId, status: 'declined' });
  if (!oldRecord) return res.status(400).json({ error: 'That juror has not declined — nothing to replace.' });

  await TournamentJury.create({ tournamentId: tournament._id, userId: newUserId, missedVotes: 0, status: 'pending' });

  await Notification.create({
    userId:  newUserId,
    type:    'tournament_jury_invite',
    payload: { tournamentId: tournament._id, tournamentName: tournament.name, openDeadline: tournament.openDeadline, url: '/tournament/' + tournament._id + '/jury-invite' },
  });

  res.json({ success: true });
});

return router;
}

// ── Feed, entries, contests, profiles and settings ────────────────────────
function pagesRoutes() {
const express       = require('express');
const router        = express.Router();
const mongoose      = require('mongoose');
const path          = require('path');
const fs            = require('fs');
const bcrypt        = require('bcrypt');
const User                  = require('../models/User');
const Entry                 = require('../models/Entry');
const Rating                = require('../models/Rating');
const Comment               = require('../models/Comment');
const CommentReport         = require('../models/CommentReport');
const ContestComment        = require('../models/ContestComment');
const Contest               = require('../models/Contest');
const ContestVote           = require('../models/ContestVote');
const Nomination            = require('../models/Nomination');
const Notification          = require('../models/Notification');
const TournamentEntry       = require('../models/TournamentEntry');
const TournamentMatch       = require('../models/TournamentMatch');
const Tournament            = require('../models/Tournament');
const Follow                = require('../models/Follow');
const ContestLoop           = require('../models/ContestLoop');
const UserAffinity          = require('../models/UserAffinity');
const WalletTransaction     = require('../models/WalletTransaction');
const ContestPayout         = require('../models/ContestPayout');
const MonthlySnapshot       = require('../models/MonthlySnapshot');
const ContestContribution   = require('../models/ContestContribution');
const EntryBookmark         = require('../models/EntryBookmark');
const UserBlock             = require('../models/UserBlock');
const ProfileShareView      = require('../models/ProfileShareView');
const { buildFeedPage }                        = require('../services/feedScorer');
const { updateAffinity, updateCreatorAffinity } = require('../services/affinityUpdater');
const { submitEntryToTournament, checkTournamentPreflight, attemptTournamentAutoDraft } = require('../services/tournamentSubmission');
const requireAuth   = require('../middleware/requireAuth');
const requireApproved = require('../middleware/requireApproved');
const upload        = require('../middleware/upload');

router.get('/guidelines', (req, res) => {
  res.render('app/guidelines', { title: 'Community Guidelines' });
});

router.get('/s/:id', async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.redirect('/');
  await Entry.findByIdAndUpdate(req.params.id, { $inc: { shareCount: 1 } }).catch(() => {});
  res.redirect('/entry/' + req.params.id);
});

router.use(requireAuth);
router.use(requireApproved);

router.get('/', (req, res) => res.redirect('/feed'));

const FEED_CANDIDATE_POOL = 150;

async function buildFeedScoringContext(currentUserId, candidates, follows, affinityDoc) {
  const ids         = candidates.map(e => e._id);
  const sixHoursAgo = new Date(Date.now() - 6  * 60 * 60 * 1000);
  const oneDayAgo   = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const followingSet = new Set(follows.map(f => f.followingId.toString()));

  const [myRatings, ratingVelocityAgg, commentVelocityAgg, activity24hAgg, activeContests] = await Promise.all([
    Rating.find({ userId: currentUserId, entryId: { $in: ids } }).select('entryId score').lean(),
    Rating.aggregate([
      { $match: { entryId: { $in: ids }, createdAt: { $gte: sixHoursAgo } } },
      { $group: { _id: '$entryId', count: { $sum: 1 } } },
    ]),
    Comment.aggregate([
      { $match: { entryId: { $in: ids }, createdAt: { $gte: sixHoursAgo } } },
      { $group: { _id: '$entryId', count: { $sum: 1 } } },
    ]),
    Promise.all([
      Rating.aggregate([
        { $match: { entryId: { $in: ids }, createdAt: { $gte: oneDayAgo } } },
        { $group: { _id: '$entryId', count: { $sum: 1 } } },
      ]),
      Comment.aggregate([
        { $match: { entryId: { $in: ids }, createdAt: { $gte: oneDayAgo } } },
        { $group: { _id: '$entryId', count: { $sum: 1 } } },
      ]),
    ]),
    Contest.find({ 'entries.entryId': { $in: ids }, status: 'active' }).select('entries').lean(),
  ]);

  const ratedMap = {};
  for (const r of myRatings) ratedMap[r.entryId.toString()] = r.score;

  const ratingVelocityMap = {};
  for (const v of ratingVelocityAgg) ratingVelocityMap[v._id.toString()] = v.count;

  const commentVelocityMap = {};
  for (const v of commentVelocityAgg) commentVelocityMap[v._id.toString()] = v.count;

  const activity24hMap = {};
  const [ratings24h, comments24h] = activity24hAgg;
  for (const v of ratings24h)  activity24hMap[v._id.toString()] = (activity24hMap[v._id.toString()] || 0) + v.count;
  for (const v of comments24h) activity24hMap[v._id.toString()] = (activity24hMap[v._id.toString()] || 0) + v.count;

  const inActiveContestSet = new Set();
  for (const c of activeContests) {
    for (const e of c.entries) inActiveContestSet.add(e.entryId.toString());
  }

  const stainScores   = affinityDoc?.stainScores   instanceof Map ? affinityDoc.stainScores   : new Map(Object.entries(affinityDoc?.stainScores   || {}));
  const creatorScores = affinityDoc?.creatorScores instanceof Map ? affinityDoc.creatorScores : new Map(Object.entries(affinityDoc?.creatorScores || {}));

  return { followingSet, ratedMap, ratingVelocityMap, commentVelocityMap, activity24hMap, inActiveContestSet, stainScores, creatorScores };
}

async function buildFeedAnnotations(feedEntries, currentUserId) {
  const feedIds = feedEntries.map(e => e._id);
  if (!feedIds.length) return { nomineesMap: {}, contestInfoMap: {}, bookmarkedIds: new Set() };

  const feedContests = await Contest.find({ 'entries.entryId': { $in: feedIds } })
    .select('entries status votingDeadline winnerEntryId voidReason').lean();

  const feedContestIds = feedContests.map(c => c._id);
  const feedNominations = feedContestIds.length
    ? await Nomination.find({ contestId: { $in: feedContestIds } })
        .populate('nomineeId', 'username avatar')
        .populate('nominatorId', 'username avatar')
        .lean()
    : [];

  const feedIdSet = new Set(feedIds.map(id => id.toString()));

  const nominationsByContest = {};
  for (const n of feedNominations) {
    const cid = n.contestId.toString();
    if (!nominationsByContest[cid]) nominationsByContest[cid] = [];
    nominationsByContest[cid].push(n);
  }

  const contestInfoMap = {};
  const nomineesMap = {};
  for (const c of feedContests) {
    const cid   = c._id.toString();
    const effSt = (c.status === 'active' && c.votingDeadline && c.votingDeadline < new Date())
      ? 'closed' : c.status;
    const nominations = nominationsByContest[cid] || [];

    for (const ce of c.entries) {
      const eid = ce.entryId?.toString();
      if (!eid || !feedIdSet.has(eid)) continue;

      if (!contestInfoMap[eid]) {
        contestInfoMap[eid] = { contestId: cid, status: effSt };
      }

      for (const n of nominations) {
        const isNominator = n.nominatorId?._id?.toString() === ce.userId?.toString();
        const opponent    = isNominator ? n.nomineeId : n.nominatorId;
        if (!opponent?.username?.value) continue;
        if (!nomineesMap[eid]) nomineesMap[eid] = [];
        nomineesMap[eid].push({
          contestId:        cid,
          username:         opponent.username?.value,
          avatar:           opponent.avatar?.value || null,
          status:           effSt === 'void' ? 'void' : n.status,
          contestStatus:    effSt,
          voteCountMine:    0,
          voteCountNominee: 0,
          contribution:     0,
          isWinner:         !!(c.winnerEntryId && c.winnerEntryId.toString() === eid),
          voidReason:       n.voidReason || null,
        });
      }
    }
  }

  const chipRankFeed = s => s === 'active' ? 0 : s === 'pending' ? 1 : s === 'closed' ? 2 : 3;
  for (const eid of Object.keys(nomineesMap)) {
    nomineesMap[eid].sort((a, b) => chipRankFeed(a.contestStatus) - chipRankFeed(b.contestStatus));
  }

  const feedBookmarks = await EntryBookmark.find({ userId: currentUserId, entryId: { $in: feedIds } }).select('entryId').lean();
  const bookmarkedIds = new Set(feedBookmarks.map(b => b.entryId.toString()));

  return { nomineesMap, contestInfoMap, bookmarkedIds };
}

router.get('/feed', async (req, res) => {
  const currentUserId = req.session.userId;

  const [blockDocs, follows, affinityDoc] = await Promise.all([
    UserBlock.find({ blockerId: currentUserId }).select('blockedId').lean(),
    Follow.find({ followerId: currentUserId }).select('followingId').lean(),
    UserAffinity.findOne({ userId: currentUserId }).lean(),
  ]);

  const blockedIds = blockDocs.map(b => b.blockedId);

  const candidates = await Entry.find({ userId: { $ne: currentUserId, $nin: blockedIds } })
    .sort({ createdAt: -1 })
    .limit(FEED_CANDIDATE_POOL)
    .populate('userId', 'username displayName avatar')
    .lean();

  if (!candidates.length) {
    return res.render('app/feed', {
      title: 'Feed', activePage: 'feed', currentUser: req.currentUser, feedEntries: [],
    });
  }

  const scoringContext = await buildFeedScoringContext(currentUserId, candidates, follows, affinityDoc);
  const feedEntries    = buildFeedPage(candidates, scoringContext, req.currentUser);
  const { nomineesMap, contestInfoMap, bookmarkedIds } = await buildFeedAnnotations(feedEntries, currentUserId);

  res.render('app/feed', {
    title:      'Feed',
    activePage: 'feed',
    currentUser: req.currentUser,
    feedEntries,
    nomineesMap,
    contestInfoMap,
    bookmarkedIds,
  });
});

router.get('/leaderboard', async (req, res) => {
  const entries = await Entry.find({ ratingCount: { $gte: 3 } })
    .sort({ ratingAvg: -1 })
    .limit(50)
    .populate('userId', 'username displayName')
    .lean();

  const items = entries.map(e => ({
    mediaUrl:    e.mediaUrl,
    title:       e.caption || '',
    authorName:  e.userId?.displayName?.value || e.userId?.username?.value || 'Unknown',
    ratingScore: e.ratingAvg,
    ratingCount: e.ratingCount,
  }));

  res.render('app/leaderboard', {
    title:      'Leaderboard',
    activePage: 'leaderboard',
    currentUser: req.currentUser,
    items,
  });
});

router.get('/search', (req, res) => {
  res.render('app/search', {
    title:      'Search',
    activePage: 'search',
    currentUser: req.currentUser,
    initialQuery:    req.query.q || '',
    initialCategory: ['people', 'entries', 'contests', 'tags'].includes(req.query.category) ? req.query.category : '',
    initialFilter:   req.query.filter || '',
  });
});

router.get('/contests', async (req, res) => {
  const currentUserId = req.currentUser._id;
  const now = new Date();

  const [rawNominations, rawContests, loopDocs] = await Promise.all([
    Nomination.find({ nomineeId: currentUserId, status: 'pending' })
      .populate('nominatorId', 'username displayName')
      .populate({
        path: 'contestId',
        populate: { path: 'entries.entryId', select: 'mediaType mediaUrl', model: 'Entry' },
      })
      .sort({ expiresAt: 1 })
      .lean(),

    Contest.find({
      tournamentId: null,
      $or: [
        { visibility: 'public' },
        { 'entries.userId': currentUserId },
      ],
      status: 'active',
      votingDeadline: { $gt: now },
    })
      .populate('entries.entryId', 'title mediaType mediaUrl')
      .populate('entries.userId', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean(),

    ContestLoop.find({ userId: currentUserId }).select('contestId').lean(),
  ]);

  const loopedInContestIds = loopDocs.map(w => w.contestId);

  const rawLoopedIn = loopedInContestIds.length
    ? await Contest.find({ _id: { $in: loopedInContestIds } })
        .populate('entries.entryId', 'title mediaType mediaUrl')
        .populate('entries.userId', 'username displayName avatar')
        .sort({ lastActivityAt: -1 })
        .lean()
    : [];

  // Build follow set across all contestant IDs from both sections
  const allContestantIds = [];
  for (const c of [...rawContests, ...rawLoopedIn]) {
    for (const e of (c.entries || [])) {
      if (e.userId?._id) allContestantIds.push(e.userId._id);
    }
  }
  const followDocs = allContestantIds.length
    ? await Follow.find({ followerId: currentUserId, followingId: { $in: allContestantIds } }).select('followingId').lean()
    : [];
  const followingSet = new Set(followDocs.map(f => f.followingId.toString()));

  const panelPendingNominations = rawNominations
    .filter(nom => nom.expiresAt > now)
    .map(nom => {
      const firstEntry = nom.contestId?.entries?.[0];
      return {
        _id:      nom._id,
        entry:    firstEntry?.entryId || null,
        nominator: {
          displayName: nom.nominatorId?.displayName?.value || nom.nominatorId?.username?.value || 'Unknown',
          username:    nom.nominatorId?.username?.value || '',
        },
        message:   nom.message,
        expiresAt: nom.expiresAt,
      };
    });

  function buildContestShape(c, statusOverride) {
    const title       = c.entries?.[0]?.entryId?.title || c.entries?.[1]?.entryId?.title || 'H2H Contest';
    const covers      = (c.entries || []).slice(0, 2).map(e => ({
      mediaUrl:  e.entryId?.mediaUrl  || '',
      mediaType: e.entryId?.mediaType || 'photo',
    }));
    const contestants = (c.entries || []).map(e => {
      const uid = e.userId?._id?.toString();
      return {
        userId:      uid || '',
        username:    e.userId?.username?.value || '',
        avatar:      e.userId?.avatar?.value || '',
        displayName: e.userId?.displayName?.value || ('@' + (e.userId?.username?.value || '')),
        isFollowing: uid ? followingSet.has(uid) : false,
        isSelf:      uid === currentUserId.toString(),
      };
    });
    return {
      _id:            c._id,
      status:         statusOverride || (c.status === 'pending' ? 'upcoming' : c.status),
      covers,
      title,
      contestants,
      votingDeadline: c.votingDeadline || null,
      visibility:     c.visibility,
    };
  }

  const contests        = rawContests.map(c => buildContestShape(c, c.status === 'pending' ? 'upcoming' : 'active'));
  const loopedInContests = rawLoopedIn.map(c => buildContestShape(c));

  res.render('app/contests', {
    title:      'Contests',
    activePage: 'contests',
    currentUser: req.currentUser,
    panelPendingNominations,
    contests,
    loopedInContests,
  });
});

router.get('/notifications', (req, res) => {
  res.render('app/notifications', {
    title:      'Notifications',
    activePage: 'notifications',
    currentUser: req.currentUser,
  });
});

// ── Entry page ────────────────────────────────────────────────────

router.get('/entry/:id', async (req, res) => {
const entry = await Entry.findById(req.params.id).populate('userId', 'username displayName avatar').catch(() => null);
  if (!entry) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  const ownerId = entry.userId._id;
  const isOwn = ownerId.toString() === req.session.userId;
  const [followDoc, activeContest, rawEntryContests, myRating, takeOnNomContestIds, entryBookmarkDoc] = await Promise.all([
    (!isOwn && req.session.userId)
      ? Follow.findOne({ followerId: req.session.userId, followingId: ownerId }).lean()
      : Promise.resolve(null),
    Contest.findOne({ 'entries.entryId': entry._id, status: { $in: ['pending', 'active'] } })
      .select('_id status voidDeadline votingDeadline').lean().catch(() => null),
    Contest.find({ 'entries.entryId': entry._id }).select('_id status entries voidDeadline votingDeadline winnerEntryId voidReason').lean(),
    (!isOwn && req.session.userId)
      ? Rating.findOne({ entryId: entry._id, userId: req.session.userId }).select('score').lean()
      : Promise.resolve(null),
    // Take-on contests where this entry is the nominee but not yet in contest.entries
    Nomination.find({ nomineeEntryId: entry._id, type: 'take_on' }).select('contestId').lean().catch(() => []),
    req.session.userId
      ? EntryBookmark.findOne({ entryId: entry._id, userId: req.session.userId }).select('_id').lean()
      : Promise.resolve(null),
  ]);

  const existingContestIds = new Set(rawEntryContests.map(c => c._id.toString()));
  const missingContestIds  = takeOnNomContestIds
    .map(n => n.contestId).filter(id => id && !existingContestIds.has(id.toString()));
  const extraContests = missingContestIds.length
    ? await Contest.find({ _id: { $in: missingContestIds } })
        .select('_id status entries voidDeadline votingDeadline winnerEntryId voidReason').lean().catch(() => [])
    : [];
  const entryContests = [...rawEntryContests, ...extraContests];

  // Resolve activeContest blind spot: pending take-ons where entry is the nominee
  const resolvedActiveContest = activeContest
    || (missingContestIds.length ? (extraContests.find(c => c.status === 'pending' || c.status === 'active') || null) : null);

  const nominations = entryContests.length
    ? await Nomination.find({
        contestId: { $in: entryContests.map(c => c._id) },
        status:    { $in: ['pending', 'accepted', 'void'] },
      })
      .populate('nomineeId', 'username displayName avatar')
      .populate('nominatorId', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean()
    : [];

  const entryContestById = {};
  for (const c of entryContests) entryContestById[c._id.toString()] = c;

  const liveContestIds = entryContests.filter(c => c.status === 'active' || c.status === 'closed').map(c => c._id);
  const entryVoteAggs  = liveContestIds.length
    ? await ContestVote.aggregate([
        { $match: { contestId: { $in: liveContestIds } } },
        { $group: { _id: { contestId: '$contestId', entryId: '$entryId' }, count: { $sum: 1 } } },
      ])
    : [];
  const entryVoteMap = {};
  for (const a of entryVoteAggs) {
    const cid = a._id.contestId.toString();
    if (!entryVoteMap[cid]) entryVoteMap[cid] = {};
    entryVoteMap[cid][a._id.entryId.toString()] = a.count;
  }

  const myEid    = entry._id.toString();
  const nominees = [];
  const seenContests = new Set();
  for (const n of nominations) {
    const cid = n.contestId.toString();
    if (seenContests.has(cid)) continue;
    seenContests.add(cid);
    const contest = entryContestById[cid];
    const voidRsn = contest?.voidReason || null;
    if (voidRsn === 'canceled') continue;
    const isNominator = n.nominatorId?._id?.toString() === ownerId.toString();
    const opponent    = isNominator ? n.nomineeId : n.nominatorId;
    const uname       = opponent?.username?.value;
    if (!uname) continue;
    const cvotes  = entryVoteMap[cid] || {};
    const oppEid  = contest?.entries?.find(e => e.entryId?.toString() !== myEid)?.entryId?.toString();
    const rawStatus = contest?.status || null;
    const effContestStatus = (rawStatus === 'active' && contest?.votingDeadline && contest.votingDeadline < new Date())
      ? 'closed' : rawStatus;
    nominees.push({
      contestId:        cid,
      username:         uname,
      displayName:      opponent.displayName?.value || uname,
      avatar:           opponent.avatar?.value || null,
      status:           effContestStatus === 'void' ? 'void' : n.status,
      voidReason:       voidRsn,
      contestStatus:    effContestStatus,
      voteCountMine:    cvotes[myEid]  || 0,
      voteCountNominee: oppEid ? (cvotes[oppEid] || 0) : 0,
      contribution:     0,
      isWinner:         !!(contest?.winnerEntryId && contest.winnerEntryId.toString() === myEid),
    });
  }

  const chipRank = s => s === 'active' ? 0 : s === 'pending' ? 1 : s === 'closed' ? 2 : 3;
  nominees.sort((a, b) => chipRank(a.contestStatus) - chipRank(b.contestStatus));

  const topLevelComments = await Comment.find({ entryId: entry._id, parentId: null, hidden: false })
    .populate('userId', 'username displayName avatar')
    .sort({ createdAt: -1 })
    .lean();

  const ratingDocs = await Rating.find({ entryId: entry._id }).sort({ createdAt: -1 }).lean();
  const raterIds = ratingDocs.map(r => r.userId);
  const raterUsers = await User.find({ _id: { $in: raterIds } }).select('username displayName avatar').lean();
  const raterMap = Object.fromEntries(raterUsers.map(u => [u._id.toString(), u]));
  const raterFollowSet = new Set();
  if (req.session.userId && raterIds.length) {
    const myFollows = await Follow.find({ followerId: req.session.userId, followingId: { $in: raterIds } }).select('followingId').lean();
    myFollows.forEach(f => raterFollowSet.add(f.followingId.toString()));
  }
  const entryRatings = ratingDocs.map(r => ({
    ...r,
    userId: raterMap[r.userId.toString()] || null,
    isFollowing: raterFollowSet.has(r.userId.toString()),
  }));

  const topLevelIds = topLevelComments.map(c => c._id);
  const replies = topLevelIds.length
    ? await Comment.find({ parentId: { $in: topLevelIds }, hidden: false })
        .populate('userId', 'username displayName avatar')
        .sort({ createdAt: 1 })
        .lean()
    : [];

  const replyMap = {};
  for (const r of replies) {
    const pid = r.parentId.toString();
    if (!replyMap[pid]) replyMap[pid] = [];
    replyMap[pid].push(r);
  }
  const comments = topLevelComments.map(c => ({ ...c, replies: replyMap[c._id.toString()] || [] }));

  const _now = Date.now();
  const _scoreComment = c => {
    const ownNet     = (c.likes?.length || 0) - (c.dislikes?.length || 0);
    const hoursOld   = (_now - new Date(c.createdAt).getTime()) / 3600000;
    const recency    = 1 / Math.pow(hoursOld + 2, 1.5);
    const replyBoost = (c.replies || []).reduce((sum, r) => {
      const rNet   = (r.likes?.length || 0) - (r.dislikes?.length || 0);
      const rHours = (_now - new Date(r.createdAt).getTime()) / 3600000;
      return sum + rNet * (1 / Math.pow(rHours + 2, 1.5));
    }, 0);
    return ownNet + replyBoost * 0.25 + recency;
  };
  comments.sort((a, b) => _scoreComment(b) - _scoreComment(a));
  const _pinned   = comments.filter(c => c.pinnedAt).sort((a, b) => new Date(a.pinnedAt) - new Date(b.pinnedAt));
  const _unpinned = comments.filter(c => !c.pinnedAt);
  comments.splice(0, comments.length, ..._pinned, ..._unpinned);

  res.render('app/entry', {
    title:       entry.title || entry.caption?.slice(0, 60) || 'Entry',
    activePage:  '',
    currentUser: req.currentUser,
    entry,
    isFollowing:    !!followDoc,
    isBookmarked:   !!entryBookmarkDoc,
    currentUserId:  req.session.userId || null,
    userRating:     myRating?.score || null,
    contestInfo: (() => {
      if (!resolvedActiveContest) return null;
      const effSt = (resolvedActiveContest.status === 'active' && resolvedActiveContest.votingDeadline && resolvedActiveContest.votingDeadline < new Date())
        ? 'closed' : resolvedActiveContest.status;
      if (effSt === 'void' || effSt === 'closed') return null;
      return { contestId: resolvedActiveContest._id.toString(), status: effSt };
    })(),
    nominees,
    comments,
    ratings: entryRatings,
  });

  // Fire-and-forget visit signal — only for other users' entries
  if (!isOwn && req.session.userId) {
    updateAffinity(req.session.userId, entry, { signal: 0.1 }).catch(() => {});
  }
});

// ── Entry edit page ───────────────────────────────────────────────

router.get('/entry/:id/edit', async (req, res) => {
  const entry = await Entry.findById(req.params.id)
    .populate('userId', 'username displayName avatar')
    .catch(() => null);
  if (!entry) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });

  if (entry.userId._id.toString() !== req.session.userId) {
    return res.status(403).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const activeContest = await Contest.findOne({
    'entries.entryId': entry._id,
    status: 'active',
  }).select('_id').lean().catch(() => null);

  if (activeContest) return res.redirect(`/contest/${activeContest._id}`);

  const [pendingContests, pendingNominations] = await Promise.all([
    Contest.find({
      entries: { $elemMatch: { entryId: entry._id, userId: req.session.userId } },
      status: 'pending',
    }).select('_id status voidDeadline').lean().catch(() => []),
    Nomination.find({ nomineeId: req.session.userId, status: 'pending', expiresAt: { $gt: new Date() } })
      .populate('nominatorId', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean()
      .catch(() => []),
  ]);

  const timedOutContestIds = new Set(pendingContests.filter(c => c.status === 'void').map(c => c._id.toString()));
  const pendingContest = pendingContests.find(c => c.status === 'pending') || null;

  const outgoingNoms = pendingContests.length
    ? await Nomination.find({
        contestId: { $in: pendingContests.map(c => c._id) },
        nominatorId: req.session.userId,
        status: 'pending',
      }).populate('nomineeId', 'username displayName avatar').lean().catch(() => [])
    : [];

  const _seenNomineeIds = new Set();
  const existingNominees = [];
  for (const n of outgoingNoms) {
    const uid = n.nomineeId._id.toString();
    if (_seenNomineeIds.has(uid)) continue;
    _seenNomineeIds.add(uid);
    existingNominees.push({
      _id:         uid,
      username:    n.nomineeId.username?.value,
      displayName: n.nomineeId.displayName?.value || n.nomineeId.username?.value,
      avatar:      n.nomineeId.avatar?.value || null,
      contestId:   n.contestId.toString(),
      timedOut:    timedOutContestIds.has(n.contestId.toString()),
    });
  }

  res.render('app/edit-entry', {
    title:            'Edit Entry',
    activePage:       '',
    currentUser:      req.currentUser,
    entry,
    pendingContestId: pendingContest ? pendingContest._id.toString() : null,
    pendingNominations,
    existingNominees,
  });
});

// ── Profile ───────────────────────────────────────────────────────

router.get('/profile', (req, res) => res.redirect(`/${req.currentUser.username}`));

// ── Settings ──────────────────────────────────────────────────────

router.get('/settings', async (req, res) => {
  const userId = req.session.userId;
  const user = await User.findById(userId).select(
    'username displayName bio avatar banner location url sex birthdate email nominationSettings privacySettings notificationSettings wallet'
  );

  const currentMonth = new Date().toISOString().slice(0, 7); // "YYYY-MM"
  const today        = new Date().getDate();

  const [monthlySnapshot, recentTransactions, totalTransactions, txMonthsRaw] = await Promise.all([
    MonthlySnapshot.findOne({ userId, month: currentMonth }).lean(),
    WalletTransaction.find({ userId }).sort({ createdAt: -1 }).limit(12).lean(),
    WalletTransaction.countDocuments({ userId }),
    WalletTransaction.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$createdAt' } } } },
      { $sort: { _id: -1 } },
    ]),
  ]);

  const successParam = req.query.success || req.query.saved || null;
  const successMsg = successParam === 'topup' ? 'Your chillies have been added to your wallet.'
                   : successParam             ? 'Settings saved.'
                   : null;

  const errorMsg = null;

  res.render('app/settings', {
    title:      'Settings',
    activePage: 'settings',
    currentUser: req.currentUser,
    user,
    nominationSettings: user?.nominationSettings || { allow: true, whoCanNominate: 'everyone' },
    privacySettings: user?.privacySettings || { whoCanDm: 'everyone', whoCanComment: 'everyone', showMatureContent: true, showAiContent: true, defaultAllowTakeOns: true, bookmarksPrivate: false },
    notifSettings: user?.notificationSettings || { inAppComments: true, inAppNominations: true, inAppContests: true, inAppPayouts: true, emailComments: true, emailNominations: true, emailContests: true, emailPayouts: true },
    wallet: {
      purchasedCHL:     user?.wallet?.purchasedCHL || 0,
      earnedCHL:        user?.wallet?.earnedCHL    || 0,
      monthlySnapshot,
      recentTransactions,
      totalTransactions,
      transactionMonths: txMonthsRaw.map(r => r._id),
      showHoldBtn:      today >= 25 && today <= 29 && monthlySnapshot?.status === 'pending',
    },
    activeTab: req.query.tab || 'profile',
    success: successMsg,
    error:   errorMsg,
  });
});

// ── Account Deletion ──────────────────────────────────────────────

router.post('/account/delete', async (req, res) => {
  const renderError = async (msg) => {
    const user = await User.findById(req.session.userId).select(
      'username displayName bio avatar banner location url sex birthdate email'
    );
    return res.render('app/settings', {
      title: 'Settings', activePage: 'settings', currentUser: req.currentUser,
      user, success: null, error: msg,
    });
  };

  const { password } = req.body;
  if (!password) return renderError('Password is required to delete your account.');

  try {
    const user = await User.findById(req.session.userId);
    if (!user) return req.session.destroy(() => res.redirect('/signup'));

    const match = await bcrypt.compare(password, user.password);
    if (!match) return renderError('Incorrect password. Account not deleted.');

    const userId = user._id;

    const entries = await Entry.find({ userId }).select('mediaUrl');

    await Rating.deleteMany({ userId });
    await Rating.deleteMany({ entryId: { $in: entries.map(e => e._id) } });
    await Comment.deleteMany({ userId });
    await CommentReport.deleteMany({ reportedBy: userId });
    await ContestVote.deleteMany({ userId });
    await Nomination.deleteMany({ $or: [{ nominatorId: userId }, { nomineeId: userId }] });
    await TournamentEntry.deleteMany({ userId });
    await Entry.deleteMany({ userId });

    for (const entry of entries) {
      if (entry.mediaUrl) {
        fs.unlink(path.join(__dirname, '../public', entry.mediaUrl), () => {});
      }
    }
    if (user.avatar?.value) fs.unlink(path.join(__dirname, '../public', user.avatar.value), () => {});
    if (user.banner?.value) fs.unlink(path.join(__dirname, '../public', user.banner.value), () => {});

    await User.findByIdAndDelete(userId);
    req.session.destroy(() => res.redirect('/signup'));
  } catch (err) {
    console.error('Account deletion error:', err);
    return renderError('Something went wrong. Please try again.');
  }
});

// ── Take On ───────────────────────────────────────────────────────

router.get('/take-on/:id', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }
  const nom = await Nomination.findById(req.params.id).select('contestId type').lean().catch(() => null);
  if (!nom || nom.type !== 'take_on' || !nom.contestId) {
    return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }
  return res.redirect('/contest/' + nom.contestId);
});

// ── Submit Entry ──────────────────────────────────────────────────

router.get('/submit', async (req, res) => {
  if (!req.currentUser.idVerified) return res.redirect('/verify-identity?reason=entry');

  const userId = req.currentUser._id;

  const [pendingNominations, userEntries] = await Promise.all([
    Nomination.find({ nomineeId: userId, status: 'pending', expiresAt: { $gt: new Date() } })
      .populate('nominatorId', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean(),
    Entry.find({ userId })
      .sort({ createdAt: -1 })
      .limit(24)
      .select('mediaUrl mediaType caption ratingAvg ratingCount')
      .lean(),
  ]);

  let acceptingNomination = null;
  if (req.query.nomination) {
    const nom = pendingNominations.find(n => n._id.toString() === req.query.nomination);
    if (nom) {
      if (nom.type === 'viewer_nomination') {
        const [sibling, preSelectedEntry] = await Promise.all([
          Nomination.findOne({ contestId: nom.contestId, _id: { $ne: nom._id } })
            .populate('nomineeId', 'username displayName avatar')
            .lean(),
          nom.preSelectedEntryId
            ? Entry.findById(nom.preSelectedEntryId).select('mediaUrl mediaType caption title').lean()
            : Promise.resolve(null),
        ]);
        acceptingNomination = {
          _id:                nom._id,
          nominator:          nom.nominatorId,
          opponent:           sibling?.nomineeId || null,
          entry:              null,
          expiresAt:          nom.expiresAt,
          message:            nom.message || null,
          contestId:          nom.contestId,
          isViewerNomination: true,
          preSelectedEntry:   preSelectedEntry || null,
          isLocked:           !!preSelectedEntry,
        };
      } else {
        const contest = await Contest.findById(nom.contestId)
          .populate('entries.entryId', 'mediaUrl mediaType title caption tags')
          .lean();
        const challEntry = contest?.entries.find(
          e => e.userId.toString() === nom.nominatorId._id.toString()
        );
        acceptingNomination = {
          _id:       nom._id,
          nominator: nom.nominatorId,
          entry:     challEntry?.hidden ? null : (challEntry?.entryId || null),
          hidden:    challEntry?.hidden || false,
          expiresAt: nom.expiresAt,
          message:   nom.message || null,
          contestId: nom.contestId,
        };
      }
    }
  }

  let challengeEntry = null;
  if (req.query.challenge && mongoose.isValidObjectId(req.query.challenge)) {
    challengeEntry = await Entry.findById(req.query.challenge)
      .populate('userId', 'username displayName avatar')
      .select('mediaUrl mediaType title caption tags userId')
      .lean()
      .catch(() => null);
  }

  let takeOnContest = null;
  if (req.query.takeOn && mongoose.isValidObjectId(req.query.takeOn)) {
    const toc = await Contest.findById(req.query.takeOn)
      .populate('entries.entryId', 'mediaUrl mediaType title caption tags')
      .lean()
      .catch(() => null);
    const tocNom = toc ? await Nomination.findOne({
      contestId:   toc._id,
      nominatorId: req.session.userId,
      type:        'take_on',
      status:      'accepted',
    }).populate('nomineeId', 'username displayName avatar').lean().catch(() => null) : null;
    if (toc && tocNom && toc.status === 'pending') {
      const opponentEntry = toc.entries?.[0]?.entryId || null;
      takeOnContest = {
        contestId:     toc._id,
        opponent:      tocNom.nomineeId,
        opponentEntry,
        voidDeadline:  toc.voidDeadline,
      };
    }
  }

  let takeOnTargetEntry = null;
  if (req.query.takeOnTargetId && mongoose.isValidObjectId(req.query.takeOnTargetId)) {
    const tote = await Entry.findById(req.query.takeOnTargetId)
      .populate('userId', 'username displayName avatar')
      .select('mediaUrl mediaType title caption userId allowTakeOns')
      .lean()
      .catch(() => null);
    if (tote && tote.allowTakeOns !== false && tote.userId._id.toString() !== req.session.userId) {
      takeOnTargetEntry = tote;
    }
  }

  let targetTournament = null;
  if (req.query.tournamentId && mongoose.isValidObjectId(req.query.tournamentId)) {
    const tournament = await Tournament.findById(req.query.tournamentId).lean();
    if (tournament) {
      const preflight = await checkTournamentPreflight(tournament, userId);
      targetTournament = { tournament, eligible: preflight.eligible, reason: preflight.reason || null };
    }
  }

  res.render('app/submit', {
    title:      'Submit Entry',
    activePage: 'submit',
    currentUser: req.currentUser,
    error: null,
    pendingNominations: acceptingNomination
      ? pendingNominations.filter(n => n._id.toString() !== acceptingNomination._id.toString())
      : pendingNominations,
    userEntries,
    acceptingNomination,
    challengeEntry,
    takeOnContest,
    takeOnTargetEntry,
    targetTournament,
  });
});

router.post('/submit', upload.entry.fields([{ name: 'entryMedia', maxCount: 1 }]), async (req, res) => {
  if (!req.currentUser.idVerified) return res.redirect('/verify-identity?reason=entry');
  const renderError = (msg) => res.render('app/submit', {
    title: 'Submit Entry', activePage: 'submit', currentUser: req.currentUser, error: msg,
    pendingNominations: [], userEntries: [], acceptingNomination: null, challengeEntry: null, takeOnContest: null,
  });

  const file = req.files?.entryMedia?.[0];
  if (!file) return renderError('Please upload a photo or video.');

  const isVideo = file.mimetype.startsWith('video/');
  if (!isVideo && file.size > 10 * 1024 * 1024) return renderError('Photo files must be under 10 MB.');

  let tags = [];
  if (req.body.tags) {
    const raw = Array.isArray(req.body.tags) ? req.body.tags : [req.body.tags];
    tags = raw.map(t => t.trim().toLowerCase()).filter(Boolean).slice(0, 6);
  }

  const takeOnContestId = req.body.takeOnContestId?.trim() || null;

  try {
    const caption = req.body.caption?.trim() || undefined;
    if (caption && caption.replace(/\s/g, '').length > 140) return renderError('Description cannot exceed 140 characters (spaces not counted).');

    const entry = await Entry.create({
      userId:    req.session.userId,
      mediaUrl:  `/uploads/entries/${file.filename}`,
      mediaType: isVideo ? 'video' : 'photo',
      caption,
      tags,
    });

    // Tournament candidacy is always resolved at upload time — either an explicit tournament
    // the uploader targeted, or an automatic stain-match draft into any other open tournament.
    const tournamentId = req.body.tournamentId?.trim() || null;
    const uploader = await User.findById(req.session.userId).select('idVerified username displayName avatar').lean();
    if (tournamentId && mongoose.isValidObjectId(tournamentId)) {
      const targetTournament = await Tournament.findById(tournamentId).lean();
      if (targetTournament) {
        await submitEntryToTournament({ tournament: targetTournament, entry, actor: uploader, autoSubmitted: false });
      }
    }
    attemptTournamentAutoDraft(entry, uploader).catch(() => {});

    const takeOnTargetId = req.body.takeOnTargetId?.trim() || null;
    if (takeOnTargetId && mongoose.isValidObjectId(takeOnTargetId)) {
      const targetEntry = await Entry.findById(takeOnTargetId).select('userId allowTakeOns').lean().catch(() => null);
      const actor = await User.findById(req.session.userId).select('username displayName avatar').lean();
      if (targetEntry && targetEntry.allowTakeOns && targetEntry.userId.toString() !== req.session.userId) {
        const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        const contest = await Contest.create({
          createdBy:    req.session.userId,
          visibility:   'public',
          status:       'pending',
          voidDeadline: expiry,
          windowHours:  72,
          entries:      [{ entryId: entry._id, userId: req.session.userId, submittedAt: new Date() }],
        });
        const nomination = await Nomination.create({
          contestId:         contest._id,
          nominatorId:       req.session.userId,
          nomineeId:         targetEntry.userId,
          expiresAt:         expiry,
          status:            'pending',
          type:              'take_on',
          challengerEntryId: entry._id,
          nomineeEntryId:    targetEntry._id,
        });
        Notification.create({
          userId:  targetEntry.userId,
          type:    'take_on_received',
          payload: {
            actorUsername:    actor?.username?.value    || 'Someone',
            actorDisplayName: actor?.displayName?.value || actor?.username?.value || 'Someone',
            actorAvatar:      actor?.avatar?.value      || null,
            contestId:        contest._id,
            nominationId:     nomination._id,
            entryId:          targetEntry._id,
            url:              '/contest/' + contest._id,
          },
        }).catch(() => {});
        return res.redirect(`/contest/${contest._id}`);
      }
    }

    res.redirect(`/entry/${entry._id}`);
  } catch (err) {
    console.error('Entry submit error:', err);
    renderError('Something went wrong. Please try again.');
  }
});

// ── Profile settings update ───────────────────────────────────────

router.post('/settings/profile', upload.profile.fields([{ name: 'avatar', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
  const { username, displayName, bio, location, url, sex, birthdate, returnTo, bannerRemove, avatarRemove, bannerPosX, bannerPosY, bannerZoom } = req.body;
  const errors = [];
  const safeReturnTo = typeof returnTo === 'string' && returnTo.startsWith('/') && !returnTo.startsWith('//')
    ? returnTo
    : null;

  const renderSettingsError = async (msg) => {
    const user = await User.findById(req.session.userId).select(
      'username displayName bio avatar banner location url sex birthdate email'
    );
    return res.render('app/settings', {
      title: 'Settings', activePage: 'settings', currentUser: req.currentUser,
      user, success: null, error: msg,
    });
  };

  const redirectWithError = (msg) => {
    if (!safeReturnTo || safeReturnTo.startsWith('/settings')) return false;
    const join = safeReturnTo.includes('?') ? '&' : '?';
    res.redirect(`${safeReturnTo}${join}editError=${encodeURIComponent(msg)}`);
    return true;
  };

  const usernameNormalized = (username || '').toLowerCase().trim();
  const hasDisplayName = Object.prototype.hasOwnProperty.call(req.body, 'displayName');
  const hasBio         = Object.prototype.hasOwnProperty.call(req.body, 'bio');
  const hasLocation    = Object.prototype.hasOwnProperty.call(req.body, 'location');
  const hasUrl         = Object.prototype.hasOwnProperty.call(req.body, 'url');
  const hasSex         = Object.prototype.hasOwnProperty.call(req.body, 'sex');
  const hasBirthdate   = Object.prototype.hasOwnProperty.call(req.body, 'birthdate');

  const displayNameTrimmed = hasDisplayName ? (displayName || '').trim() : null;
  const bioTrimmed         = hasBio         ? (bio         || '').trim() : null;
  const locationTrimmed    = hasLocation    ? (location    || '').trim() : null;
  const urlTrimmed         = hasUrl         ? (url         || '').trim() : null;
  const sexTrimmed         = hasSex         ? (sex         || '').trim() : null;

  if (!usernameNormalized || !/^[a-z][a-z0-9]{2,14}$/.test(usernameNormalized)) {
    errors.push('Username must start with a letter, contain only letters and digits, and be 3-15 characters.');
  }
  if (hasDisplayName && displayNameTrimmed && displayNameTrimmed.length > 50) {
    errors.push('Display name cannot exceed 50 characters.');
  }
  if (hasDisplayName && displayNameTrimmed && displayNameTrimmed.split(/\s+/).filter(Boolean).length > 3) {
    errors.push('Display name can be at most 3 words.');
  }
  const bioCharCount = bioTrimmed ? bioTrimmed.replace(/\s/g, '').length : 0;
  if (hasBio && bioCharCount > 0 && (bioCharCount < 20 || bioCharCount > 220)) {
    errors.push('Bio must be between 20 and 220 characters (spaces not counted).');
  }
  if (hasUrl && urlTrimmed.length > 200) {
    errors.push('Website URL cannot exceed 200 characters.');
  }
  if (hasSex && sexTrimmed && !['male', 'female', 'other', 'prefer-not-to-say'].includes(sexTrimmed)) {
    errors.push('Invalid sex value.');
  }

  let birthdateValue = null;
  if (hasBirthdate && birthdate) {
    const parsedBirthdate = new Date(birthdate);
    if (Number.isNaN(parsedBirthdate.getTime())) {
      errors.push('Invalid birthdate.');
    } else {
      birthdateValue = parsedBirthdate;
    }
  }

  if (errors.length) {
    const redirected = redirectWithError(errors[0]);
    if (redirected) return redirected;
    return renderSettingsError(errors[0]);
  }

  // Fetch current user to check username edit limits and compare values
  const currentUserDoc = await User.findById(req.session.userId).select(
    'username displayName bio location url sex birthdate avatar banner'
  );

  const currentUsername = currentUserDoc.username?.value || '';
  const isChangingUsername = currentUsername !== usernameNormalized;

  if (isChangingUsername) {
    const histLen   = currentUserDoc.username?.history?.length || 1;
    const editCount = histLen - 1;
    if (editCount >= 3) {
      const redirected = redirectWithError('You have reached the lifetime limit of 3 username changes.');
      if (redirected) return redirected;
      return renderSettingsError('You have reached the lifetime limit of 3 username changes.');
    }
    const fourteenDaysAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
    const recentEdits = (currentUserDoc.username?.history || []).slice(1)
      .filter(h => new Date(h.setAt) > fourteenDaysAgo);
    if (recentEdits.length >= 2) {
      const redirected = redirectWithError('You can only change your username twice within a 14-day period.');
      if (redirected) return redirected;
      return renderSettingsError('You can only change your username twice within a 14-day period.');
    }
  }

  const taken = await User.findOne({ 'username.value': usernameNormalized, _id: { $ne: req.session.userId } });
  if (taken) {
    const redirected = redirectWithError('Username already taken.');
    if (redirected) return redirected;
    return renderSettingsError('Username already taken.');
  }

  const now    = new Date();
  const setOp  = {};
  const pushOp = {};

  setOp['username.value'] = usernameNormalized;
  if (isChangingUsername) {
    pushOp['username.history'] = { value: usernameNormalized, setAt: now, source: 'edit_profile' };
  }

  if (hasDisplayName) {
    const newVal = displayNameTrimmed || null;
    const oldVal = currentUserDoc.displayName?.value || null;
    setOp['displayName.value'] = newVal;
    if (newVal !== oldVal) {
      pushOp['displayName.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (hasBio) {
    const newVal = bioTrimmed || null;
    const oldVal = currentUserDoc.bio?.value || null;
    setOp['bio.value'] = newVal;
    if (newVal !== oldVal) {
      pushOp['bio.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (hasLocation) {
    const newVal = locationTrimmed || null;
    const oldVal = currentUserDoc.location?.value || null;
    setOp['location.value'] = newVal;
    if (newVal !== oldVal) {
      pushOp['location.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (hasUrl) {
    const newVal = urlTrimmed || null;
    const oldVal = currentUserDoc.url?.value || null;
    setOp['url.value'] = newVal;
    if (newVal !== oldVal) {
      pushOp['url.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (hasSex) {
    const newVal = sexTrimmed || null;
    const oldVal = currentUserDoc.sex?.value || null;
    setOp['sex.value'] = newVal;
    if (newVal !== oldVal) {
      pushOp['sex.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (hasBirthdate) {
    const newVal    = birthdateValue || null;
    const oldValStr = currentUserDoc.birthdate?.value ? new Date(currentUserDoc.birthdate.value).toISOString() : null;
    const newValStr = newVal ? newVal.toISOString() : null;
    setOp['birthdate.value'] = newVal;
    if (newValStr !== oldValStr) {
      pushOp['birthdate.history'] = { value: newVal, setAt: now, source: 'edit_profile' };
    }
  }

  if (req.files?.avatar?.[0]) {
    const avatarPath = `/uploads/avatars/${req.files.avatar[0].filename}`;
    const oldVal     = currentUserDoc.avatar?.value || null;
    setOp['avatar.value'] = avatarPath;
    if (avatarPath !== oldVal) {
      pushOp['avatar.history'] = { value: avatarPath, setAt: now, source: 'edit_profile' };
    }
  } else if (avatarRemove === '1') {
    const oldVal = currentUserDoc.avatar?.value || null;
    setOp['avatar.value'] = null;
    if (oldVal !== null) {
      pushOp['avatar.history'] = { value: null, setAt: now, source: 'edit_profile' };
    }
  }

  const bpx  = parseFloat(bannerPosX);
  const bpy  = parseFloat(bannerPosY);
  const bzm  = parseFloat(bannerZoom);
  const posX = isNaN(bpx) ? 0.5 : Math.max(0, Math.min(1, bpx));
  const posY = isNaN(bpy) ? 0.5 : Math.max(0, Math.min(1, bpy));
  const zoom = isNaN(bzm) ? 1   : Math.max(1, bzm);

  if (req.files?.banner?.[0]) {
    const bannerPath = `/uploads/banners/${req.files.banner[0].filename}`;
    const oldVal     = currentUserDoc.banner?.value || null;
    setOp['banner.value'] = bannerPath;
    setOp['banner.posX']  = posX;
    setOp['banner.posY']  = posY;
    setOp['banner.zoom']  = zoom;
    if (bannerPath !== oldVal) {
      pushOp['banner.history'] = { value: bannerPath, setAt: now, source: 'edit_profile' };
    }
  } else if (bannerRemove === '1') {
    const oldVal = currentUserDoc.banner?.value || null;
    setOp['banner.value'] = null;
    setOp['banner.posX']  = 0.5;
    setOp['banner.posY']  = 0.5;
    setOp['banner.zoom']  = 1;
    if (oldVal !== null) {
      pushOp['banner.history'] = { value: null, setAt: now, source: 'edit_profile' };
    }
  } else if (currentUserDoc.banner?.value) {
    setOp['banner.posX'] = posX;
    setOp['banner.posY'] = posY;
    setOp['banner.zoom'] = zoom;
  }

  const updateDoc = { $set: setOp };
  if (Object.keys(pushOp).length) updateDoc.$push = pushOp;

  await User.findByIdAndUpdate(req.session.userId, updateDoc);

  if (safeReturnTo) {
    const join = safeReturnTo.includes('?') ? '&' : '?';
    return res.redirect(`${safeReturnTo}${join}saved=1`);
  }
  res.redirect('/settings?saved=1');
});

// ── Privacy settings update ───────────────────────────────────────

router.post('/settings/privacy', async (req, res) => {
  const allow          = req.body.nominationAllow === 'true';
  const validWho       = ['everyone', 'followers_only', 'followees_only', 'mutual_follow'];
  const whoCanNominate = validWho.includes(req.body.whoCanNominate) ? req.body.whoCanNominate : 'everyone';

  const validDmScope = ['everyone', 'followers_only', 'mutual_follow'];
  const whoCanDm = validDmScope.includes(req.body.whoCanDm) ? req.body.whoCanDm : 'everyone';

  const validCommentScope = ['everyone', 'followers_only', 'contributors_only'];
  const whoCanComment = validCommentScope.includes(req.body.whoCanComment) ? req.body.whoCanComment : 'everyone';

  await User.findByIdAndUpdate(req.session.userId, {
    $set: {
      'nominationSettings.allow':            allow,
      'nominationSettings.whoCanNominate':   whoCanNominate,
      'privacySettings.whoCanDm':            whoCanDm,
      'privacySettings.whoCanComment':       whoCanComment,
      'privacySettings.showMatureContent':   req.body.showMatureContent   === 'true',
      'privacySettings.showAiContent':       req.body.showAiContent       === 'true',
      'privacySettings.defaultAllowTakeOns': req.body.defaultAllowTakeOns === 'true',
      'privacySettings.bookmarksPrivate':    req.body.bookmarksPrivate    === 'true',
    },
  });
  res.redirect('/settings?tab=privacy&saved=privacy');
});

// ── Notification settings update ──────────────────────────────────

router.post('/settings/notifications', async (req, res) => {
  await User.findByIdAndUpdate(req.session.userId, {
    $set: {
      'notificationSettings.inAppComments':    req.body.inAppComments    === 'true',
      'notificationSettings.inAppNominations': req.body.inAppNominations === 'true',
      'notificationSettings.inAppContests':    req.body.inAppContests    === 'true',
      'notificationSettings.inAppPayouts':     req.body.inAppPayouts     === 'true',
      'notificationSettings.emailComments':    req.body.emailComments    === 'true',
      'notificationSettings.emailNominations': req.body.emailNominations === 'true',
      'notificationSettings.emailContests':    req.body.emailContests    === 'true',
      'notificationSettings.emailPayouts':     req.body.emailPayouts     === 'true',
    },
  });
  res.redirect('/settings?tab=notifications&saved=1');
});

// ── Contest page ──────────────────────────────────────────────────

router.get('/contest/:id', async (req, res) => {
  const contest = await Contest.findById(req.params.id)
    .populate('entries.entryId', 'mediaUrl mediaType title caption tags ratingAvg ratingCount aiGenerated')
    .populate('createdBy', 'username displayName avatar')
    .lean()
    .catch(() => null);

  if (!contest) {
    return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });
  }

  const nomCE = contest.entries.find(e => e.userId.toString() === contest.createdBy._id.toString());
  const resCE = contest.entries.find(e => e.userId.toString() !== contest.createdBy._id.toString());

  const userIds = contest.entries.map(e => e.userId);
  const users   = await User.find({ _id: { $in: userIds } }).select('username displayName avatar').lean();
  const userMap = {};
  users.forEach(u => { userMap[u._id.toString()] = u; });

  const myId   = req.session.userId?.toString();
  const myVote = await ContestVote.findOne({ contestId: contest._id, userId: req.session.userId })
    .select('entryId').lean().catch(() => null);

  const voteCounts = {};
  let totalVotes = 0;
  if (myVote || contest.status === 'closed') {
    const agg = await ContestVote.aggregate([
      { $match: { contestId: contest._id } },
      { $group: { _id: '$entryId', count: { $sum: 1 } } },
    ]);
    for (const r of agg) { voteCounts[r._id.toString()] = r.count; totalVotes += r.count; }
  }

  const effectiveStatus = (contest.status === 'active' && contest.votingDeadline && contest.votingDeadline < new Date())
    ? 'closed'
    : contest.status;

  const canVote = effectiveStatus === 'active' && !myVote;
  const isNominator = !!(myId && contest.createdBy?._id?.toString() === myId);
  const isNominee   = !!(myId && resCE && resCE.userId.toString() === myId);

  function buildSide(ce) {
    if (!ce) return null;
    const uid  = ce.userId.toString();
    const user = userMap[uid] || null;
    const eid  = ce.entryId?._id?.toString();
    return {
      userId:    uid,
      user,
      entry:     ce.entryId || null,
      entryId:   eid || null,
      hidden:    ce.hidden || false,
      voteCount: voteCounts[eid] || 0,
      votePct:   totalVotes > 0 ? Math.round(((voteCounts[eid] || 0) / totalVotes) * 100) : 0,
      isWinner:  !!(contest.winnerEntryId && eid && contest.winnerEntryId.toString() === eid),
      isMine:    uid === myId,
      iVotedFor: !!(myVote && eid && myVote.entryId.toString() === eid),
    };
  }

  const left  = buildSide(nomCE);
  const right = resCE ? buildSide(resCE) : null;

  let nomineeUser = null;
  let nomineeEntry = null;
  let pendingTakeOnNomId = null;
  if (!right && contest.status === 'pending') {
    const nom = await Nomination.findOne({ contestId: contest._id, status: 'pending' })
      .select('nomineeId nominatorId type _id nomineeEntryId').lean().catch(() => null);
    if (nom) {
      nomineeUser = await User.findById(nom.nomineeId).select('username displayName avatar').lean().catch(() => null);
      if (nom.type === 'take_on' && myId && nom.nomineeId.toString() === myId) {
        pendingTakeOnNomId = nom._id.toString();
      }
      if (nom.type === 'take_on' && nom.nomineeEntryId) {
        nomineeEntry = await Entry.findById(nom.nomineeEntryId)
          .select('mediaUrl mediaType title caption tags aiGenerated').lean().catch(() => null);
      }
    }
  }

  const followingIds = {};
  if (req.session.userId) {
    const targetIds = [
      left?.userId,
      right ? right.userId : (nomineeUser ? nomineeUser._id : null),
    ].filter(Boolean);
    if (targetIds.length) {
      const follows = await Follow.find({
        followerId:  req.session.userId,
        followingId: { $in: targetIds },
      }).select('followingId').lean().catch(() => []);
      follows.forEach(f => { followingIds[f.followingId.toString()] = true; });
    }
  }

  const isLoopedIn = req.session.userId
    ? !!(await ContestLoop.exists({ contestId: contest._id, userId: req.session.userId }))
    : false;

  const isTiebreakerMatch = contest.tournamentId
    ? !!(await TournamentMatch.exists({ contestId: contest._id, isTiebreakerMatch: true }))
    : false;

  const voidLabelMap = { expired: 'No Response', declined: 'Denied', canceled: 'Canceled', nominee_forfeit: 'Forfeited', nominator_forfeit: 'Forfeit Win' };
  const statusLabel = effectiveStatus === 'void'
    ? (voidLabelMap[contest.voidReason] || 'No Response')
    : ({ pending: 'Pending', active: 'Live', closed: 'Contest has ended' }[effectiveStatus] || effectiveStatus);

  const topLevelComments = await ContestComment.find({ contestId: contest._id, parentId: null, hidden: false })
    .populate('userId', 'username displayName avatar')
    .sort({ createdAt: -1 })
    .lean()
    .catch(() => []);

  const topLevelIds = topLevelComments.map(c => c._id);
  const allReplies  = topLevelIds.length
    ? await ContestComment.find({ parentId: { $in: topLevelIds }, hidden: false })
        .populate('userId', 'username displayName avatar')
        .sort({ createdAt: 1 })
        .lean()
        .catch(() => [])
    : [];

  const replyMap = {};
  for (const r of allReplies) {
    const pid = r.parentId.toString();
    if (!replyMap[pid]) replyMap[pid] = [];
    replyMap[pid].push(r);
  }
  const comments = topLevelComments.map(c => ({ ...c, replies: replyMap[c._id.toString()] || [] }));

  const _nowCC = Date.now();
  const _scoreCC = c => {
    const ownNet     = (c.likes?.length || 0) - (c.dislikes?.length || 0);
    const hoursOld   = (_nowCC - new Date(c.createdAt).getTime()) / 3600000;
    const recency    = 1 / Math.pow(hoursOld + 2, 1.5);
    const replyBoost = (c.replies || []).reduce((sum, r) => {
      const rNet   = (r.likes?.length || 0) - (r.dislikes?.length || 0);
      const rHours = (_nowCC - new Date(r.createdAt).getTime()) / 3600000;
      return sum + rNet * (1 / Math.pow(rHours + 2, 1.5));
    }, 0);
    return ownNet + replyBoost * 0.25 + recency;
  };
  comments.sort((a, b) => _scoreCC(b) - _scoreCC(a));

  const participantIds = [left?.userId, right?.userId].filter(Boolean);
  const relatedContests = participantIds.length
    ? await Contest.find({
        _id:               { $ne: contest._id },
        'entries.userId':  { $in: participantIds },
        visibility:        'public',
        status:            { $nin: ['void'] },
      })
      .sort({ createdAt: -1 })
      .limit(10)
      .select('_id status entries createdAt votingDeadline')
      .populate('entries.entryId', 'mediaUrl mediaType')
      .lean()
      .catch(() => [])
    : [];

  const relatedUserIds = [...new Set(relatedContests.flatMap(c => c.entries.map(e => e.userId.toString())))];
  const relatedUserDocs = relatedUserIds.length
    ? await User.find({ _id: { $in: relatedUserIds } }).select('username displayName avatar').lean().catch(() => [])
    : [];
  const relatedUserMap = {};
  relatedUserDocs.forEach(u => { relatedUserMap[u._id.toString()] = u; });

  // Contribution data
  const contestEntryIds = contest.entries.map(e => e.entryId?._id || e.entryId).filter(Boolean);
  const [contributionAgg, myContributions, viewerUser, allContributions] = await Promise.all([
    ContestContribution.aggregate([
      { $match: { contestId: contest._id, status: { $ne: 'withdrawn' } } },
      { $group: { _id: '$entryId', totalCHL: { $sum: '$amountCHL' } } },
    ]),
    req.session.userId
      ? ContestContribution.find({ contestId: contest._id, contributorId: req.session.userId, status: { $ne: 'withdrawn' } })
          .select('entryId amountCHL status').lean().catch(() => [])
      : Promise.resolve([]),
    req.session.userId
      ? User.findById(req.session.userId).select('wallet').lean().catch(() => null)
      : Promise.resolve(null),
    ContestContribution.find({ contestId: contest._id, status: { $ne: 'withdrawn' } })
      .select('entryId contributorId amountCHL')
      .populate('contributorId', 'username displayName avatar')
      .lean().catch(() => []),
  ]);

  const grossByEntry = {};
  for (const r of contributionAgg) { grossByEntry[r._id.toString()] = r.totalCHL; }

  const myContribMap = {};
  for (const c of myContributions) { myContribMap[c.entryId.toString()] = c; }

  const topContributionEntryId = contestEntryIds.length
    ? contestEntryIds.reduce((best, eid) => {
        const id = eid.toString();
        return (grossByEntry[id] || 0) > (grossByEntry[best?.toString()] || 0) ? eid : best;
      }, null)
    : null;

  const leftEntryId  = left?.entryId  ? left.entryId.toString()  : null;
  const rightEntryId = right?.entryId ? right.entryId.toString() : null;
  const sortByAmount = (a, b) => b.amountCHL - a.amountCHL;
  const contribRankLeft  = leftEntryId
    ? allContributions.filter(c => c.entryId.toString() === leftEntryId).sort(sortByAmount)
    : [];
  const contribRankRight = rightEntryId
    ? allContributions.filter(c => c.entryId.toString() === rightEntryId).sort(sortByAmount)
    : [];

  res.render('app/contest', {
    title:      'H2H Contest',
    activePage: '',
    currentUser: req.currentUser,
    contest,
    left,
    right,
    nomineeUser,
    nomineeEntry,
    followingIds,
    myVote,
    canVote,
    isNominator,
    isNominee,
    isLoopedIn,
    isTiebreakerMatch,
    pendingTakeOnNomId,
    totalVotes,
    showVotes:   !!(myVote || effectiveStatus === 'closed'),
    effectiveStatus,
    statusLabel,
    topContributionEntryId,
    grossByEntry,
    myContribMap,
    contribRankLeft,
    contribRankRight,
    viewerBalanceCHL: (viewerUser?.wallet?.purchasedCHL || 0) + (viewerUser?.wallet?.earnedCHL || 0),
    canContribute:    effectiveStatus === 'active',
    comments,
    relatedContests,
    relatedUserMap,
  });
});

// ── Public profile — must be last to avoid swallowing other routes ─

router.get('/:username', async (req, res) => {
  const user = await User.findOne({ 'username.value': req.params.username.toLowerCase() })
    .select('username displayName bio avatar banner location sex birthdate url createdAt nominationSettings privacySettings wallet pinnedEntryId');

  if (!user) return res.status(404).render('app/404', { title: 'Not Found', currentUser: req.currentUser });

  const isOwn   = user._id.toString() === req.session.userId;
  const entries = await Entry.find({ userId: user._id }).sort({ createdAt: -1 });

  const pinnedEntryId = user.pinnedEntryId?.toString() || null;
  if (pinnedEntryId) {
    const idx = entries.findIndex(e => e._id.toString() === pinnedEntryId);
    if (idx > 0) entries.unshift(entries.splice(idx, 1)[0]);
  }

  const entryIds = entries.map(e => e._id);

  const showBookmarksTab = isOwn || !(user.privacySettings?.bookmarksPrivate);

  const [followerCount, followingCount, nominationsAccepted, userContests, userTournamentEntries, followDoc, blockDoc, viewerBookmarkDocs, profileBookmarkDocs] = await Promise.all([
    Follow.countDocuments({ followingId: user._id }),
    Follow.countDocuments({ followerId: user._id }),
    Nomination.countDocuments({ nomineeId: user._id, status: 'accepted' }),
    Contest.find({ 'entries.userId': user._id }).sort({ createdAt: -1 }).select('_id status voidReason entries votingDeadline winnerEntryId createdAt').populate('entries.entryId', 'mediaUrl caption').populate('entries.userId', 'username displayName avatar').lean(),
    TournamentEntry.find({ userId: user._id }).sort({ submittedAt: -1 }).populate('tournamentId', 'name status prizes').populate('entryId', 'mediaUrl caption').lean(),
    (!isOwn && req.session.userId) ? Follow.findOne({ followerId: req.session.userId, followingId: user._id }).lean() : Promise.resolve(null),
    (!isOwn && req.session.userId) ? UserBlock.findOne({ blockerId: req.session.userId, blockedId: user._id }).lean() : Promise.resolve(null),
    (entryIds.length && req.session.userId) ? EntryBookmark.find({ userId: req.session.userId, entryId: { $in: entryIds } }).select('entryId').lean() : Promise.resolve([]),
    showBookmarksTab ? EntryBookmark.find({ userId: user._id }).sort({ createdAt: -1 }).populate('entryId', 'mediaUrl mediaType ratingAvg ratingCount').lean() : Promise.resolve([]),
  ]);

  let firstPrizes = 0, secondPrizes = 0, thirdPrizes = 0;
  for (const te of userTournamentEntries) {
    if (!te.tournamentId || te.tournamentId.status !== 'closed') continue;
    if (!te.eliminated && te.knockoutRound === 'Final') firstPrizes++;
    else if (te.eliminated && te.knockoutRound === 'Final') secondPrizes++;
    else if (!te.eliminated && te.knockoutRound === '3rd') thirdPrizes++;
  }

  const isFollowing = !!followDoc;
  const isBlocked   = !!blockDoc;
  const viewerBookmarkedIdSet = new Set(viewerBookmarkDocs.map(b => b.entryId.toString()));
  const bookmarkedEntries = profileBookmarkDocs.filter(b => b.entryId).map(b => b.entryId);

  const contestStatusPriority = { active: 0, pending: 1, scheduled: 1, closed: 2, void: 3 };
  userContests.sort((a, b) => {
    const pa = contestStatusPriority[a.status] ?? 3;
    const pb = contestStatusPriority[b.status] ?? 3;
    return pa !== pb ? pa - pb : new Date(b.createdAt) - new Date(a.createdAt);
  });

  // Build a follow-status set for H2H opponent users
  let h2hFollowedIdSet = new Set();
  if (req.session.userId) {
    const oppIds = [];
    for (const c of userContests) {
      const opp = c.entries.find(e => {
        const uid = e.userId?._id ? e.userId._id.toString() : e.userId?.toString();
        return uid !== user._id.toString();
      });
      const oppId = opp?.userId?._id ?? opp?.userId;
      if (oppId) oppIds.push(oppId);
    }
    if (oppIds.length) {
      const h2hFollowDocs = await Follow.find({ followerId: req.session.userId, followingId: { $in: oppIds } }).select('followingId').lean();
      h2hFollowedIdSet = new Set(h2hFollowDocs.map(f => f.followingId.toString()));
    }
  }

  const contestMap = {};
  for (const c of userContests) {
    const effSt = (c.status === 'active' && c.votingDeadline && c.votingDeadline < new Date())
      ? 'closed' : c.status;
    if (effSt === 'void') continue;
    for (const ce of c.entries) {
      const eid = ce.entryId?._id?.toString();
      if (eid && !contestMap[eid]) {
        contestMap[eid] = { contestId: c._id.toString(), status: effSt };
      }
    }
  }

  const contestToEntryId = {};
  for (const c of userContests) {
    for (const ce of c.entries) {
      const eid = ce.entryId?._id?.toString();
      const uid = ce.userId?._id?.toString() ?? ce.userId?.toString();
      if (eid && uid === user._id.toString()) contestToEntryId[c._id.toString()] = eid;
    }
  }
  const profileNominations = userContests.length
    ? await Nomination.find({
        contestId:   { $in: userContests.map(c => c._id) },
        nominatorId: user._id,
        status:      { $in: ['pending', 'accepted', 'void'] },
      }).populate('nomineeId', 'username displayName avatar').lean()
    : [];

  profileNominations.sort((a, b) => {
    const rank = s => s === 'accepted' ? 0 : s === 'pending' ? 1 : 2;
    return rank(a.status) - rank(b.status);
  });

  // Nominations where this user is the NOMINEE and submitted an entry — shows nominator's info
  const receivedNominations = await Nomination.find({
    nomineeId:      user._id,
    status:         { $in: ['accepted', 'void'] },
    nomineeEntryId: { $ne: null },
  }).populate('nominatorId', 'username displayName avatar').lean().catch(() => []);

  const profileContestById = {};
  for (const c of userContests) profileContestById[c._id.toString()] = c;

  const profileLiveCIds = userContests
    .filter(c => c.status === 'active' || c.status === 'closed')
    .map(c => c._id);
  const profileVoteAggs = profileLiveCIds.length
    ? await ContestVote.aggregate([
        { $match: { contestId: { $in: profileLiveCIds } } },
        { $group: { _id: { contestId: '$contestId', entryId: '$entryId' }, count: { $sum: 1 } } },
      ])
    : [];
  const profileVoteMap = {};
  for (const a of profileVoteAggs) {
    const cid = a._id.contestId.toString();
    if (!profileVoteMap[cid]) profileVoteMap[cid] = {};
    profileVoteMap[cid][a._id.entryId.toString()] = a.count;
  }

  const profileContribAggs = profileLiveCIds.length
    ? await ContestContribution.aggregate([
        { $match: { contestId: { $in: profileLiveCIds }, status: { $ne: 'withdrawn' } } },
        { $group: { _id: { contestId: '$contestId', entryId: '$entryId' }, total: { $sum: '$amountCHL' } } },
      ])
    : [];
  const profileContribMap = {};
  for (const a of profileContribAggs) {
    const cid = a._id.contestId.toString();
    if (!profileContribMap[cid]) profileContribMap[cid] = {};
    profileContribMap[cid][a._id.entryId.toString()] = a.total;
  }

  const nomineesMap = {};
  const seenContestsPerEntry = {};
  for (const n of profileNominations) {
    const eid = contestToEntryId[n.contestId.toString()];
    if (!eid) continue;
    const uname = n.nomineeId?.username?.value;
    if (!uname) continue;
    const cid = n.contestId.toString();
    if (!seenContestsPerEntry[eid]) seenContestsPerEntry[eid] = new Set();
    if (seenContestsPerEntry[eid].has(cid)) continue;
    seenContestsPerEntry[eid].add(cid);
    if (!nomineesMap[eid]) nomineesMap[eid] = [];
    const pContest = profileContestById[cid];
    const rawSt    = pContest?.status || null;
    const effSt    = (rawSt === 'active' && pContest?.votingDeadline && pContest.votingDeadline < new Date())
      ? 'closed' : rawSt;
    const cvotes   = profileVoteMap[cid] || {};
    const oppEid   = pContest?.entries?.find(e => e.entryId?._id?.toString() !== eid)?.entryId?._id?.toString();
    nomineesMap[eid].push({
      contestId:         cid,
      username:          uname,
      avatar:            n.nomineeId.avatar?.value || null,
      status:            effSt === 'void' ? 'void' : n.status,
      contestStatus:     effSt,
      voteCountMine:     cvotes[eid]    || 0,
      voteCountNominee:  oppEid ? (cvotes[oppEid] || 0) : 0,
      contribution:      0,
      isWinner:          !!(pContest?.winnerEntryId && pContest.winnerEntryId.toString() === eid),
    });
  }

  // Entries where user was the nominee — show the nominator's badge
  for (const n of receivedNominations) {
    const eid   = n.nomineeEntryId?.toString();
    const uname = n.nominatorId?.username?.value;
    if (!eid || !uname) continue;
    const cid = n.contestId.toString();
    if (!seenContestsPerEntry[eid]) seenContestsPerEntry[eid] = new Set();
    if (seenContestsPerEntry[eid].has(cid)) continue;
    seenContestsPerEntry[eid].add(cid);
    if (!nomineesMap[eid]) nomineesMap[eid] = [];
    const pContest = profileContestById[cid];
    const rawSt    = pContest?.status || null;
    const effSt    = (rawSt === 'active' && pContest?.votingDeadline && pContest.votingDeadline < new Date())
      ? 'closed' : rawSt;
    const cvotes   = profileVoteMap[cid] || {};
    const oppEid   = pContest?.entries?.find(e => e.entryId?._id?.toString() !== eid)?.entryId?._id?.toString();
    nomineesMap[eid].push({
      contestId:        cid,
      username:         uname,
      avatar:           n.nominatorId?.avatar?.value || null,
      status:           effSt === 'void' ? 'void' : n.status,
      contestStatus:    effSt,
      voteCountMine:    cvotes[eid]   || 0,
      voteCountNominee: oppEid ? (cvotes[oppEid] || 0) : 0,
      contribution:     0,
      isWinner:         !!(pContest?.winnerEntryId && pContest.winnerEntryId.toString() === eid),
    });
  }

  const chipRankProfile = s => s === 'active' ? 0 : s === 'pending' ? 1 : s === 'closed' ? 2 : 3;
  for (const eid of Object.keys(nomineesMap)) {
    nomineesMap[eid].sort((a, b) => chipRankProfile(a.contestStatus) - chipRankProfile(b.contestStatus));
  }

  const ratedEntries = entries.filter(e => e.ratingCount > 0);
  const overallRank = ratedEntries.length
    ? (ratedEntries.reduce((s, e) => s + e.ratingAvg, 0) / ratedEntries.length).toFixed(1)
    : null;
  const totalRatingCount = ratedEntries.reduce((s, e) => s + e.ratingCount, 0);

  const title = user.displayName?.value
    ? `${user.displayName.value} - @${user.username.value} on AllThingsAprons.com`
    : `@${user.username.value} on AllThingsAprons.com`;

  let canNominate = false;
  if (!isOwn && req.session.userId && !isBlocked) {
    const ns  = user.nominationSettings;
    const who = ns?.whoCanNominate || 'everyone';
    if (ns?.allow !== false) {
      if (who === 'everyone') {
        canNominate = true;
      } else if (who === 'followers_only') {
        canNominate = isFollowing;
      } else if (who === 'followees_only') {
        const rev = await Follow.exists({ followerId: user._id, followingId: req.session.userId });
        canNominate = !!rev;
      } else if (who === 'mutual_follow') {
        const rev = await Follow.exists({ followerId: user._id, followingId: req.session.userId });
        canNominate = isFollowing && !!rev;
      }
    }
  }

  if (!isOwn && req.session.userId && req.query.ref === 'share') {
    ProfileShareView.create({
      viewerId:      req.session.userId,
      profileUserId: user._id,
      referer:       req.headers.referer || req.headers.referrer || '',
      userAgent:     req.headers['user-agent'] || '',
    }).catch(() => {});
  }

  res.render('app/profile', {
    title,
    activePage: isOwn ? 'profile' : '',
    currentUser: req.currentUser,
    profileUser: user,
    entries,
    followerCount,
    followingCount,
    nominationsAccepted,
    firstPrizes,
    secondPrizes,
    thirdPrizes,
    overallRank,
    totalRatingCount,
    isOwn,
    isFollowing,
    isBlocked,
    canNominate,
    userContests,
    h2hFollowedIdSet: [...h2hFollowedIdSet],
    profileVoteMap,
    profileContribMap,
    userTournamentEntries,
    contestMap,
    nomineesMap,
    pinnedEntryId,
    showBookmarksTab,
    bookmarkedEntries,
    viewerBookmarkedIdSet,
    editError: typeof req.query.editError === 'string' ? req.query.editError : null,
  });

  // Fire-and-forget creator affinity signal — viewing someone else's profile
  if (!isOwn && req.session.userId) {
    updateCreatorAffinity(req.session.userId, user._id, 0.05).catch(() => {});
  }
});

router.get('/api/feed/entries', async (req, res) => {
  const page          = Math.max(1, parseInt(req.query.page, 10) || 1);
  const currentUserId = req.session.userId;

  const [blockDocs, follows, affinityDoc] = await Promise.all([
    UserBlock.find({ blockerId: currentUserId }).select('blockedId').lean(),
    Follow.find({ followerId: currentUserId }).select('followingId').lean(),
    UserAffinity.findOne({ userId: currentUserId }).lean(),
  ]);

  const blockedIds = blockDocs.map(b => b.blockedId);

  const candidates = await Entry.find({ userId: { $ne: currentUserId, $nin: blockedIds } })
    .sort({ createdAt: -1 })
    .skip(page * FEED_CANDIDATE_POOL)
    .limit(FEED_CANDIDATE_POOL)
    .populate('userId', 'username displayName avatar')
    .lean();

  if (!candidates.length) return res.json({ html: '', hasMore: false });

  const scoringContext = await buildFeedScoringContext(currentUserId, candidates, follows, affinityDoc);
  const feedEntries    = buildFeedPage(candidates, scoringContext, req.currentUser);

  if (!feedEntries.length) return res.json({ html: '', hasMore: false });

  const { nomineesMap, contestInfoMap, bookmarkedIds } = await buildFeedAnnotations(feedEntries, currentUserId);

  res.render('app/partials/feedEntryBlock', {
    entries: feedEntries,
    nomineesMap,
    contestInfoMap,
    bookmarkedIds,
    currentUser: req.currentUser,
  }, (err, html) => {
    if (err) return res.json({ html: '', hasMore: false });
    res.json({ html, hasMore: candidates.length >= FEED_CANDIDATE_POOL });
  });
});

return router;
}

// Mounted first in server.js, before the sign-in gate below: sign-up and log-in have to answer logged-out
// visitors. The identity check and support threads check the sign-in themselves.
const signIn = express.Router();

signIn.use('/', authRoutes());
signIn.use('/verify-identity', verifyIdentityRoutes());
signIn.use('/contact', contactRoutes());

signIn.routes = [
  { method: 'GET', path: '/signup', label: 'Sign-up page' },
  { method: 'POST', path: '/auth/send-otp', label: 'Email a sign-up code' },
  { method: 'POST', path: '/signup', label: 'Create an account' },
  { method: 'GET', path: '/login', label: 'Log-in page' },
  { method: 'POST', path: '/login', label: 'Log in' },
  { method: 'POST', path: '/logout', label: 'Log out' },
  { method: 'GET', path: '/verify-identity', label: 'Identity check page' },
  { method: 'GET', path: '/verify-identity/code', label: 'New selfie code' },
  { method: 'POST', path: '/verify-identity', label: 'Send ID photos for review' },
  { method: 'GET', path: '/contact', label: 'Support threads' },
  { method: 'GET', path: '/contact/new', label: 'Open a support thread' },
  { method: 'GET', path: '/contact/thread/:threadId', label: 'One support thread' },
  { method: 'GET', path: '/contact/thread/:threadId/messages', label: 'Messages in a support thread' },
  { method: 'POST', path: '/contact/thread/:threadId/messages', label: 'Send a support message' },
  { method: 'GET', path: '/contact/unread', label: 'Unread support message count' },
];

// The order here is part of how the app behaves. followRoutes() starts with requireAuth and requireApproved
// on every path, so that gate covers everything after it in this router, and the API after that.
const router = express.Router();
const explore = exploreRoutes();

router.use('/', followRoutes());
router.use('/wallet', injectNotificationCount, injectRightPanelData, walletRoutes());
router.use('/messages', injectNotificationCount, injectRightPanelData, messagesRoutes());
router.use('/notifications', injectNotificationCount, injectRightPanelData, notificationsRoutes());
router.use('/', injectNotificationCount, injectRightPanelData, explore);
router.use('/', injectNotificationCount, injectRightPanelData, tournamentsRoutes());
router.use('/', injectNotificationCount, injectRightPanelData, pagesRoutes());

router.routes = [
  { method: 'POST', path: '/follow/:username', label: 'Follow a user' },
  { method: 'POST', path: '/unfollow/:username', label: 'Unfollow a user' },
  { method: 'GET', path: '/wallet/topup', label: 'Buy CHL' },
  { method: 'GET', path: '/wallet/checkout', label: 'Checkout' },
  { method: 'POST', path: '/wallet/checkout', label: 'Pay at checkout (stub)' },
  { method: 'GET', path: '/wallet/transactions', label: 'Wallet history' },
  { method: 'GET', path: '/wallet/transactions/download', label: 'Download wallet history' },
  { method: 'GET', path: '/wallet/transaction/:id', label: 'One wallet transaction' },
  { method: 'POST', path: '/wallet/hold-payout', label: 'Hold the monthly auto-payout' },
  { method: 'GET', path: '/messages', label: 'Direct messages' },
  { method: 'GET', path: '/messages/:username', label: 'Conversation with a user' },
  { method: 'GET', path: '/messages/:username/history', label: 'Older messages in a conversation' },
  { method: 'POST', path: '/messages/:username/send', label: 'Send a direct message' },
  { method: 'GET', path: '/notifications', label: 'Notifications' },
  { method: 'POST', path: '/notifications/:id/read', label: 'Mark a notification read' },
  { method: 'POST', path: '/notifications/read-all', label: 'Mark all notifications read' },
  { method: 'GET', path: '/explore', label: 'Explore' },
  { method: 'GET', path: '/api/explore/entries', label: 'More Explore entries' },
  { method: 'GET', path: '/tournaments', label: 'Tournaments' },
  { method: 'GET', path: '/tournaments/create', label: 'Start a new tournament' },
  { method: 'GET', path: '/tournaments/create/step1', label: 'New tournament, step 1' },
  { method: 'POST', path: '/tournaments/create/step1', label: 'Save new tournament, step 1' },
  { method: 'GET', path: '/tournaments/create/step2', label: 'New tournament, step 2' },
  { method: 'POST', path: '/tournaments/create/step2', label: 'Save new tournament, step 2' },
  { method: 'POST', path: '/tournaments/fund', label: 'Fund a tournament draft' },
  { method: 'GET', path: '/tournaments/create/step3', label: 'New tournament, step 3' },
  { method: 'POST', path: '/tournaments/create/step3', label: 'Save new tournament, step 3' },
  { method: 'GET', path: '/tournaments/create/step4', label: 'New tournament, step 4' },
  { method: 'POST', path: '/tournaments/create/step4', label: 'Save new tournament, step 4' },
  { method: 'GET', path: '/tournaments/create/step5', label: 'New tournament, step 5' },
  { method: 'POST', path: '/tournaments/create/step5', label: 'Save new tournament, step 5' },
  { method: 'GET', path: '/tournament/:id/edit', label: 'Edit a tournament' },
  { method: 'GET', path: '/tournament/:id/edit/step1', label: 'Edit tournament, step 1' },
  { method: 'POST', path: '/tournament/:id/edit/step1', label: 'Save tournament edit, step 1' },
  { method: 'GET', path: '/tournament/:id/edit/step2', label: 'Edit tournament, step 2' },
  { method: 'POST', path: '/tournament/:id/edit/step2', label: 'Save tournament edit, step 2' },
  { method: 'GET', path: '/tournament/:id/edit/step3', label: 'Edit tournament, step 3' },
  { method: 'POST', path: '/tournament/:id/edit/step3', label: 'Save tournament edit, step 3' },
  { method: 'GET', path: '/tournament/:id/edit/step4', label: 'Edit tournament, step 4' },
  { method: 'POST', path: '/tournament/:id/edit/step4', label: 'Save tournament edit, step 4' },
  { method: 'GET', path: '/tournament/:id/edit/step5', label: 'Edit tournament, step 5' },
  { method: 'POST', path: '/tournament/:id/edit/step5', label: 'Save tournament edit, step 5' },
  { method: 'GET', path: '/tournament/:id', label: 'One tournament' },
  { method: 'POST', path: '/tournament/:id/cancel', label: 'Cancel own tournament' },
  { method: 'POST', path: '/tournament/:id/entry/withdraw', label: 'Withdraw from a tournament' },
  { method: 'POST', path: '/tournament/:id/loop-in', label: 'Loop in to a tournament' },
  { method: 'POST', path: '/tournament/:id/entry/:teId/loop-in', label: 'Loop in to a candidate' },
  { method: 'POST', path: '/tournament/:id/report', label: 'Report a tournament' },
  { method: 'POST', path: '/tournament/:id/comments', label: 'Comment on a tournament' },
  { method: 'PATCH', path: '/tournament/:id/comments/:cid', label: 'Edit a tournament comment' },
  { method: 'DELETE', path: '/tournament/:id/comments/:cid', label: 'Delete a tournament comment' },
  { method: 'POST', path: '/tournament/:id/comments/:cid/report', label: 'Report a tournament comment' },
  { method: 'POST', path: '/tournament/:id/comments/:cid/react', label: 'React to a tournament comment' },
  { method: 'GET', path: '/tournament/:id/review', label: 'Review candidates' },
  { method: 'GET', path: '/tournament/:id/jury-vote/:matchId', label: 'Jury vote on a match tie' },
  { method: 'GET', path: '/tournament/:id/organizer-vote/:matchId', label: 'Organizer vote on a match tie' },
  { method: 'GET', path: '/tournament/:id/group-jury-vote/:groupId', label: 'Jury vote on a group tie' },
  { method: 'GET', path: '/tournament/:id/group-organizer-vote/:groupId', label: 'Organizer vote on a group tie' },
  { method: 'GET', path: '/tournament/:id/jury-invite', label: 'Jury invite' },
  { method: 'POST', path: '/tournament/:id/jury-invite/respond', label: 'Answer a jury invite' },
  { method: 'GET', path: '/tournament/:id/jury/manage', label: 'Manage the jury' },
  { method: 'POST', path: '/tournament/:id/jury/replace', label: 'Replace a juror who declined' },
  { method: 'GET', path: '/guidelines', label: 'Community guidelines' },
  { method: 'GET', path: '/s/:id', label: 'Shared entry link' },
  { method: 'GET', path: '/', label: 'Redirects to /feed' },
  { method: 'GET', path: '/feed', label: 'Feed' },
  { method: 'GET', path: '/leaderboard', label: 'Leaderboard' },
  { method: 'GET', path: '/search', label: 'Search' },
  { method: 'GET', path: '/contests', label: 'Contests' },
  { method: 'GET', path: '/notifications', label: 'Notifications, never reached: the /notifications router answers first' },
  { method: 'GET', path: '/entry/:id', label: 'One entry' },
  { method: 'GET', path: '/entry/:id/edit', label: 'Edit an entry' },
  { method: 'GET', path: '/profile', label: 'Own profile' },
  { method: 'GET', path: '/settings', label: 'Settings' },
  { method: 'POST', path: '/account/delete', label: 'Delete own account' },
  { method: 'GET', path: '/take-on/:id', label: 'Take-on invite' },
  { method: 'GET', path: '/submit', label: 'Submit an entry page' },
  { method: 'POST', path: '/submit', label: 'Submit an entry' },
  { method: 'POST', path: '/settings/profile', label: 'Save profile settings' },
  { method: 'POST', path: '/settings/privacy', label: 'Save privacy settings' },
  { method: 'POST', path: '/settings/notifications', label: 'Save notification settings' },
  { method: 'GET', path: '/contest/:id', label: 'One contest' },
  { method: 'GET', path: '/:username', label: 'Profile of a user' },
];

module.exports = router;
module.exports.signIn = signIn;
module.exports.getPeopleSubSections = explore.getPeopleSubSections;
