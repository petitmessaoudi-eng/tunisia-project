// ============================================================
//  server.js  —  MongoDB + JWT Secured Backend
//  Dependencies: express, mongoose, bcryptjs, jsonwebtoken,
//                multer, cookie-parser, cors, dotenv
// ============================================================
require('dotenv').config();
const express      = require('express');
const path         = require('path');
const multer       = require('multer');
const cookieParser = require('cookie-parser');
const cors         = require('cors');
const mongoose     = require('mongoose');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI  = process.env.MONGO_URI  || 'mongodb://127.0.0.1:27017/tunisian-platform';
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING';
const JWT_EXPIRES = '7d';
const fs = require('fs');
if (!fs.existsSync('./uploads')){
    fs.mkdirSync('./uploads');
}
// ─── Middleware ───────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true,
  exposedHeaders: ['Authorization']
}));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ─── Multer ───────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, 'uploads/'),
  filename:    (_req,  file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// ─── MongoDB Connection ───────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected:', MONGO_URI))
  .catch(err => { console.error('❌ MongoDB connection error:', err); process.exit(1); });

// ============================================================
//  MONGOOSE SCHEMAS & MODELS
// ============================================================

// ── Rating sub-schema ─────────────────────────────────────────
const RatingSchema = new mongoose.Schema({
  userId:    { type: String, required: true },
  stars:     { type: Number, min: 1, max: 5, required: true },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

// ── Comment sub-schema ────────────────────────────────────────
const CommentSchema = new mongoose.Schema({
  userId:    String,
  userName:  String,
  text:      String,
  images:    [String],
  timestamp: { type: Date, default: Date.now }
});

// ── Post schema ───────────────────────────────────────────────
const PostSchema = new mongoose.Schema({
  title:          { type: String, required: true },
  description:    { type: String, default: '' },
  subject:        String,
  branch:         { type: String, default: 'عام' },
  year:           String,
  type:           String,
  fileUrl:        { type: String, default: '' },
  fileName:       { type: String, default: '' },
  imageUrls:      [String],
  teacherName:    { type: String, default: '' },
  youtubeLink:    { type: String, default: '' },
  uploadedBy:     String,
  uploadedByName: String,
  status:         { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  isPinned:       { type: Boolean, default: false },
  views:          { type: Number, default: 0 },
  downloads:      { type: Number, default: 0 },
  ratings:        [RatingSchema],
  avgRating:      { type: Number, default: 0 },
  ratingsCount:   { type: Number, default: 0 },
  comments:       [CommentSchema],
  createdAt:      { type: Date, default: Date.now }
});

// ── Interaction / Request schema ──────────────────────────────
const RequestSchema = new mongoose.Schema({
  userId:      String,
  userName:    String,
  subject:     String,
  branch:      String,
  year:        String,
  description: String,
  status:      { type: String, default: 'open' },
  responses:   { type: Number, default: 0 },
  createdAt:   { type: Date, default: Date.now }
});

// ── User schema ───────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  name:     { type: String, required: true },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  xp:       { type: Number, default: 0 },
  level:    { type: Number, default: 1 },
  avatar:   { type: String, default: '' },
  bio:      { type: String, default: '' },
  year:     { type: String, default: '' },
  branch:   { type: String, default: '' },
  joinedAt: { type: Date, default: Date.now }
});

// ── Report schema ─────────────────────────────────────────────
const ReportSchema = new mongoose.Schema({
  reportedBy:     String,       // userId
  reportedByName: String,
  reason:         { type: String, default: '' },
  targetType:     { type: String, enum: ['post', 'comment'], required: true },
  postId:         { type: String, required: true },
  commentId:      { type: String, default: null },  // null if reporting a post
  postTitle:      String,
  commentText:    String,
  status:         { type: String, enum: ['pending', 'resolved', 'ignored'], default: 'pending' },
  createdAt:      { type: Date, default: Date.now }
});

const Post    = mongoose.model('Post',    PostSchema);
const Request = mongoose.model('Request', RequestSchema);
const User    = mongoose.model('User',    UserSchema);
const Report  = mongoose.model('Report',  ReportSchema);

// ─── Helpers ──────────────────────────────────────────────────
const calculateLevel = (xp) => Math.floor(xp / 100) + 1;

const safeUser = (user) => ({
  id:        user._id.toString(),
  email:     user.email,
  name:      user.name,
  role:      user.role,
  xp:        user.xp,
  level:     user.level,
  avatar:    user.avatar  || '',
  bio:       user.bio     || '',
  year:      user.year    || '',
  branch:    user.branch  || '',
  joinedAt:  user.joinedAt
});

const signToken = (user) =>
  jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

// ============================================================
//  MIDDLEWARE
// ============================================================

/** Verifies JWT from Authorization header (Bearer <token>). */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يجب تسجيل الدخول أولاً' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'الجلسة منتهية أو غير صالحة' });
    req.user = payload;   // { id, role }
    next();
  });
}

/** Requires admin role — must be used AFTER authenticateToken. */
function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'هذا الإجراء مخصص للمسؤولين فقط' });
}

// ============================================================
//  AUTH ROUTES
// ============================================================

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name)
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists)
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });

    const hashed = await bcrypt.hash(password, 12);
    const user = await new User({ email, password: hashed, name }).save();

    const token = signToken(user);
    res.json({ success: true, token, user: safeUser(user) });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'خطأ في التسجيل' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

    const token = signToken(user);
    res.json({ success: true, token, user: safeUser(user) });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'خطأ في تسجيل الدخول' });
  }
});

// ============================================================
//  PUBLIC ROUTES
// ============================================================

// GET /api/stats
app.get('/api/stats', async (_req, res) => {
  try {
    const [totalPosts, totalUsers, totalRequests, dlAgg] = await Promise.all([
      Post.countDocuments({ status: 'approved' }),
      User.countDocuments(),
      Request.countDocuments(),
      Post.aggregate([{ $group: { _id: null, total: { $sum: '$downloads' } } }])
    ]);
    const pendingPosts   = await Post.countDocuments({ status: 'pending' });
    const totalDownloads = dlAgg[0]?.total || 0;
    res.json({ totalPosts, totalUsers, totalDownloads, pendingPosts, totalRequests });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'خطأ في جلب الإحصائيات' });
  }
});

// GET /api/posts
app.get('/api/posts', async (req, res) => {
  try {
    const { status, branch, year, subject, type, pinned, panicMode, uploadedBy } = req.query;
    const query = {};

    if (status)           query.status   = status;
    if (branch)           query.branch   = branch;
    if (year)             query.year     = year;
    if (subject)          query.subject  = subject;
    if (type)             query.type     = type;
    if (pinned === 'true') query.isPinned = true;
    if (uploadedBy)        query.uploadedBy = uploadedBy;
    if (panicMode === 'true') query.type  = { $in: ['ملخص', 'فيديو'] };

    const posts = await Post.find(query)
      .sort({ isPinned: -1, createdAt: -1 })
      .lean();

    // حقن صورة الرافع لكل منشور
    const uploaderIds = [...new Set(posts.map(p => p.uploadedBy).filter(Boolean))];
    let uploaderMap = {};
    if (uploaderIds.length > 0) {
      const users = await User.find({ _id: { $in: uploaderIds } }, { _id: 1, avatar: 1 }).lean();
      users.forEach(u => { uploaderMap[u._id.toString()] = u.avatar || ''; });
    }

    // Normalize _id → id + inject uploaderAvatar
    const normalized = posts.map(p => ({
      ...p,
      id: p._id.toString(),
      uploaderAvatar: p.uploadedBy ? (uploaderMap[p.uploadedBy] || '') : ''
    }));
    res.json({ posts: normalized });
  } catch (err) {
    console.error('Get posts error:', err);
    res.status(500).json({ error: 'خطأ في جلب المنشورات' });
  }
});

// GET /api/posts/:id
app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    ).lean();
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });

    // جلب صور أصحاب التعليقات من قاعدة البيانات مباشرة
    if (post.comments && post.comments.length > 0) {
      // جمع IDs المستخدمين الفريدة (بما فيهم صاحب المنشور)
      const userIds = [...new Set(
        [post.uploadedBy, ...post.comments.map(c => c.userId)].filter(Boolean)
      )];

      // جلب بيانات المستخدمين دفعة واحدة
      const users = await User.find(
        { _id: { $in: userIds } },
        { _id: 1, avatar: 1, name: 1 }
      ).lean();

      // بناء map سريع userId → { avatar, name }
      const userMap = {};
      users.forEach(u => {
        userMap[u._id.toString()] = { avatar: u.avatar || '', name: u.name || '' };
      });

      // حقن userAvatar في كل تعليق
      post.comments = post.comments.map(c => ({
        ...c,
        userAvatar: c.userId ? (userMap[c.userId]?.avatar || '') : '',
        userName: c.userId ? (userMap[c.userId]?.name || c.userName || 'مجهول') : (c.userName || 'مجهول'),
      }));

      // حقن صورة صاحب المنشور
      if (post.uploadedBy && userMap[post.uploadedBy]) {
        post.uploaderAvatar = userMap[post.uploadedBy].avatar || '';
      }
    } else if (post.uploadedBy) {
      // لا توجد تعليقات لكن نجلب صورة صاحب المنشور على الأقل
      const uploader = await User.findById(post.uploadedBy, { avatar: 1 }).lean();
      post.uploaderAvatar = uploader?.avatar || '';
    }

    res.json({ post: { ...post, id: post._id.toString() } });
  } catch (err) {
    console.error('Get post error:', err);
    res.status(500).json({ error: 'خطأ في جلب المنشور' });
  }
});

// POST /api/posts/:id/download  (public – anyone may trigger, counter only)
app.post('/api/posts/:id/download', async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { $inc: { downloads: 1 } },
      { new: true }
    ).lean();
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });
    res.json({ success: true, fileUrl: post.fileUrl });
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'خطأ في التحميل' });
  }
});

// GET /api/requests  (public)
app.get('/api/requests', async (_req, res) => {
  try {
    const requests = await Request.find().sort({ createdAt: -1 }).lean();
    res.json({ requests: requests.map(r => ({ ...r, id: r._id.toString() })) });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب الطلبات' });
  }
});

// GET /api/user/:id  (public)
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).lean();
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب بيانات المستخدم' });
  }
});

// ============================================================
//  PROTECTED ROUTES  (require valid JWT)
// ============================================================

// POST /api/upload
app.post(
  '/api/upload',
  authenticateToken,
  upload.fields([{ name: 'file', maxCount: 1 }, { name: 'images', maxCount: 10 }]),
  async (req, res) => {
    try {
      const { title, description, subject, branch, year, type, teacherName, youtubeLink } = req.body;

      let fileUrl = '', fileName = '';
      if (req.files?.file?.[0]) {
        fileUrl  = `/uploads/${req.files.file[0].filename}`;
        fileName = req.files.file[0].originalname;
      }
      const imageUrls = req.files?.images?.map(img => `/uploads/${img.filename}`) || [];

      const post = await new Post({
        title, description, subject, branch, year, type,
        fileUrl, fileName, imageUrls, teacherName, youtubeLink,
        uploadedBy:     req.user.id,
        uploadedByName: req.body.userName || 'مجهول',
        status: 'pending'
      }).save();

      // Award XP
      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        { $inc: { xp: 50 } },
        { new: true }
      );
      if (updatedUser) {
        updatedUser.level = Math.floor(updatedUser.xp / 100) + 1;
        await updatedUser.save();
      }

      res.json({ success: true, post: { ...post.toObject(), id: post._id.toString() } });
    } catch (err) {
      console.error('Upload error:', err);
      res.status(500).json({ error: 'خطأ في رفع الملف' });
    }
  }
);

// POST /api/posts/:id/comments
app.post(
  '/api/posts/:id/comments',
  authenticateToken,
  upload.array('images', 5),
  async (req, res) => {
    try {
      const { text } = req.body;
      const images   = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];

      const post = await Post.findById(req.params.id);
      if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });

      // جلب الاسم من قاعدة البيانات لضمان صحته
      const commenter = await User.findById(req.user.id).lean();
      const comment = {
        userId:   req.user.id,
        userName: commenter?.name || req.body.userName || 'مجهول',
        text,
        images
      };
      post.comments.push(comment);
      await post.save();

      // Award XP
      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        { $inc: { xp: 10 } },
        { new: true }
      );
      if (updatedUser) {
        updatedUser.level = Math.floor(updatedUser.xp / 100) + 1;
        await updatedUser.save();
      }

      const saved = post.comments[post.comments.length - 1];
      res.json({ success: true, comment: { ...saved.toObject(), id: saved._id.toString() } });
    } catch (err) {
      console.error('Comment error:', err);
      res.status(500).json({ error: 'خطأ في إضافة التعليق' });
    }
  }
);

// POST /api/posts/:id/rate
app.post('/api/posts/:id/rate', authenticateToken, async (req, res) => {
  try {
    const stars = parseInt(req.body.rating, 10);
    if (!stars || stars < 1 || stars > 5)
      return res.status(400).json({ error: 'التقييم يجب أن يكون بين 1 و5' });

    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });

    // Remove previous vote from this user, then add new one
    post.ratings = post.ratings.filter(r => r.userId !== req.user.id);
    post.ratings.push({ userId: req.user.id, stars });

    const total = post.ratings.reduce((s, r) => s + r.stars, 0);
    post.avgRating   = parseFloat((total / post.ratings.length).toFixed(1));
    post.ratingsCount = post.ratings.length;
    await post.save();

    res.json({ success: true, avgRating: post.avgRating, ratingsCount: post.ratingsCount });
  } catch (err) {
    console.error('Rate error:', err);
    res.status(500).json({ error: 'خطأ في التقييم' });
  }
});

// POST /api/requests  (protected)
app.post('/api/requests', authenticateToken, async (req, res) => {
  try {
    const { subject, branch, year, description } = req.body;
    const user = await User.findById(req.user.id);
    const request = await new Request({
      userId:   req.user.id,
      userName: user?.name || 'مجهول',
      subject, branch, year, description
    }).save();
    res.json({ success: true, request: { ...request.toObject(), id: request._id.toString() } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في إنشاء الطلب' });
  }
});

// ============================================================
//  PROFILE ROUTES  (require valid JWT)
// ============================================================

// POST /api/profile/update
app.post('/api/profile/update', authenticateToken, async (req, res) => {
  try {
    const { name, year, branch, bio } = req.body;
    if (!name || name.trim().length < 3)
      return res.status(400).json({ error: 'الاسم يجب أن يكون 3 أحرف على الأقل' });

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { name: name.trim(), year: year || '', branch: branch || '', bio: bio || '' },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'خطأ في تحديث البيانات' });
  }
});

// POST /api/profile/avatar  (multipart file upload)
app.post('/api/profile/avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    let avatarUrl = '';

    if (req.file) {
      // صورة مرفوعة كملف — الأفضل
      avatarUrl = `/uploads/${req.file.filename}`;
    } else if (req.body.avatar) {
      // base64 كـ fallback (مع التحقق من الحجم)
      if (req.body.avatar.length > 4 * 1024 * 1024)
        return res.status(400).json({ error: 'حجم الصورة كبير جداً' });
      avatarUrl = req.body.avatar;
    } else {
      return res.status(400).json({ error: 'لا توجد صورة' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { avatar: avatarUrl },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) {
    console.error('Avatar update error:', err);
    res.status(500).json({ error: 'خطأ في تحديث الصورة' });
  }
});

// POST /api/profile/password
app.post('/api/profile/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    if (newPassword.length < 6)
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Password update error:', err);
    res.status(500).json({ error: 'خطأ في تحديث كلمة المرور' });
  }
});

// DELETE /api/profile/delete
app.delete('/api/profile/delete', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'كلمة المرور مطلوبة' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'كلمة المرور غير صحيحة' });

    await User.findByIdAndDelete(req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'خطأ في حذف الحساب' });
  }
});

// ============================================================
//  ADMIN ROUTES  (require JWT + admin role)
// ============================================================

// GET /api/admin/pending
app.get('/api/admin/pending', authenticateToken, isAdmin, async (_req, res) => {
  try {
    const posts = await Post.find({ status: 'pending' }).sort({ createdAt: -1 }).lean();
    res.json({ posts: posts.map(p => ({ ...p, id: p._id.toString() })) });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المنشورات المعلقة' });
  }
});

// POST /api/admin/approve/:id
app.post('/api/admin/approve/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { status: 'approved' },
      { new: true }
    ).lean();
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });
    res.json({ success: true, post: { ...post, id: post._id.toString() } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الموافقة' });
  }
});

// DELETE /api/admin/delete/:id
app.delete('/api/admin/delete/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const post = await Post.findByIdAndDelete(req.params.id);
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الحذف' });
  }
});

// POST /api/admin/pin/:id
app.post('/api/admin/pin/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });
    post.isPinned = !post.isPinned;
    await post.save();
    res.json({ success: true, post: { ...post.toObject(), id: post._id.toString() } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في التثبيت' });
  }
});

// POST /api/reports  (protected — any logged-in user)
app.post('/api/reports', authenticateToken, async (req, res) => {
  try {
    const { targetType, postId, commentId, reason } = req.body;
    if (!targetType || !postId) return res.status(400).json({ error: 'بيانات الإبلاغ غير مكتملة' });

    const post = await Post.findById(postId).lean();
    if (!post) return res.status(404).json({ error: 'المنشور غير موجود' });

    let commentText = null;
    if (targetType === 'comment' && commentId) {
      const comment = post.comments?.find(c => c._id.toString() === commentId);
      commentText = comment ? comment.text : null;
    }

    const user = await User.findById(req.user.id).lean();
    const report = await new Report({
      reportedBy:     req.user.id,
      reportedByName: user?.name || 'مجهول',
      reason,
      targetType,
      postId,
      commentId: commentId || null,
      postTitle:   post.title,
      commentText,
      status: 'pending'
    }).save();

    res.json({ success: true, report: { ...report.toObject(), id: report._id.toString() } });
  } catch (err) {
    console.error('Report error:', err);
    res.status(500).json({ error: 'خطأ في إرسال الإبلاغ' });
  }
});

// GET /api/admin/reports  (admin only)
app.get('/api/admin/reports', authenticateToken, isAdmin, async (_req, res) => {
  try {
    const reports = await Report.find({ status: 'pending' }).sort({ createdAt: -1 }).lean();
    res.json({ reports: reports.map(r => ({ ...r, id: r._id.toString() })) });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب الإبلاغات' });
  }
});

// DELETE /api/admin/reports/:id/delete-content  (admin — delete the reported content and resolve report)
app.delete('/api/admin/reports/:id/delete-content', authenticateToken, isAdmin, async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: 'الإبلاغ غير موجود' });

    if (report.targetType === 'post') {
      await Post.findByIdAndDelete(report.postId);
    } else if (report.targetType === 'comment' && report.commentId) {
      await Post.findByIdAndUpdate(report.postId, {
        $pull: { comments: { _id: new mongoose.Types.ObjectId(report.commentId) } }
      });
    }

    report.status = 'resolved';
    await report.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete reported content error:', err);
    res.status(500).json({ error: 'خطأ في حذف المحتوى' });
  }
});

// POST /api/admin/reports/:id/ignore  (admin — ignore the report)
app.post('/api/admin/reports/:id/ignore', authenticateToken, isAdmin, async (req, res) => {
  try {
    const report = await Report.findByIdAndUpdate(req.params.id, { status: 'ignored' }, { new: true });
    if (!report) return res.status(404).json({ error: 'الإبلاغ غير موجود' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في تجاهل الإبلاغ' });
  }
});
// دالة لإنشاء المدير تلقائياً عند تشغيل السيرفر
async function seedAdmin() {
  try {
    const User = mongoose.model('User'); // تأكد أن موديل المستخدم مُعرف مسبقاً
    const adminExists = await User.findOne({ role: 'admin' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@1234', 12);
      await User.create({
        email: 'admin@platform.tn',
        password: hashedPassword,
        name: 'المسؤول الرئيسي',
        role: 'admin'
      });
      console.log('✅ تم إنشاء حساب المدير التلقائي بنجاح');
    }
  } catch (err) {
    console.error('❌ فشل إنشاء حساب المدير:', err);
  }
}

// تعديل سطر الاتصال ليفعل الدالة فور النجاح
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    seedAdmin(); // استدعاء الدالة هنا
  })
  .catch(err => console.error('Could not connect to MongoDB', err));
// ─── Catch-all ────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});