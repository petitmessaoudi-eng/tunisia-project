require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  email:    { type: String, unique: true, lowercase: true },
  password: String,
  name:     String,
  role:     { type: String, default: 'user' },
  xp:       { type: Number, default: 0 },
  level:    { type: Number, default: 1 },
  joinedAt: { type: Date,   default: Date.now }
});

const User = mongoose.model('User', UserSchema);

async function createAdmin() {
  await mongoose.connect(process.env.MONGO_URI);
  console.log('✅ Connected to MongoDB');

  const existing = await User.findOne({ email: 'admin@platform.tn' });
  if (existing) {
    console.log('⚠️  Admin already exists!');
    process.exit(0);
  }

  const hashed = await bcrypt.hash('Admin@1234', 12);
  await User.create({
    email:    'admin@platform.tn',
    password: hashed,
    name:     'المسؤول',
    role:     'admin',
    xp:       0,
    level:    1
  });

  console.log('🎉 Admin created successfully!');
  console.log('📧 Email:    admin@platform.tn');
  console.log('🔑 Password: Admin@1234');
  process.exit(0);
}

createAdmin().catch(err => { console.error(err); process.exit(1); });