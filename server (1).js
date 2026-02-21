// server.js - Complete Express + Socket.IO backend
// Run: npm install express mysql2 socket.io bcrypt jsonwebtoken cors dotenv nodemailer multer uuid qrcode

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/pool');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'friendsconnect-secret-key-2024';

// Database connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'friendsconnect',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Email transporter (configure with your SMTP)
const emailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || ''
    }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Create uploads directory if not exists
const uploadDirs = ['uploads', 'uploads/profiles', 'uploads/posts', 'uploads/messages', 'uploads/groups', 'uploads/voice'];
uploadDirs.forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const type = req.params.type || 'posts';
        cb(null, `uploads/${type}/`);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|webm|mp3|wav|m4a/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) cb(null, true);
        else cb(new Error('Invalid file type'));
    }
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await db.query('SELECT * FROM users WHERE id = ? AND is_banned = FALSE', [decoded.userId]);
        
        if (users.length === 0) return res.status(403).json({ error: 'User not found or banned' });
        
        req.user = users[0];
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, fullname, birthdate } = req.body;
    
    if (!username || !email || !password || !fullname) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    try {
        // Check existing user
        const [existing] = await db.query(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            [username, email]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Generate verification token
        const verificationToken = uuidv4();
        
        // Insert user
        const [result] = await db.query(
            `INSERT INTO users (username, email, password, fullname, birthdate, verification_token, ip_address) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, email, hashedPassword, fullname, birthdate || null, verificationToken, req.ip]
        );
        
        // Check for fake account indicators
        await checkFakeAccount(result.insertId, req.ip, email);
        
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await db.query(
            'INSERT INTO otp_codes (email, code, type, expires_at) VALUES (?, ?, "verification", DATE_ADD(NOW(), INTERVAL 15 MINUTE))',
            [email, otp]
        );
        
        // Send verification email
        await sendVerificationEmail(email, otp);
        
        res.status(201).json({ 
            message: 'Registration successful. Please check your email for verification code.',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Verify email with OTP
app.post('/api/auth/verify-email', async (req, res) => {
    const { email, otp } = req.body;
    
    try {
        const [otpRecords] = await db.query(
            'SELECT * FROM otp_codes WHERE email = ? AND code = ? AND type = "verification" AND used = FALSE AND expires_at > NOW()',
            [email, otp]
        );
        
        if (otpRecords.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
        
        await db.query('UPDATE otp_codes SET used = TRUE WHERE id = ?', [otpRecords[0].id]);
        await db.query('UPDATE users SET email_verified = TRUE WHERE email = ?', [email]);
        
        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password, deviceInfo } = req.body;
    
    try {
        const [users] = await db.query(
            'SELECT * FROM users WHERE (email = ? OR username = ?) AND is_banned = FALSE',
            [email, email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        if (!user.email_verified) {
            return res.status(401).json({ error: 'Please verify your email first' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        
        // Store session
        await db.query(
            'INSERT INTO sessions (user_id, token, device_info, ip_address) VALUES (?, ?, ?, ?)',
            [user.id, token, deviceInfo || 'Unknown', req.ip]
        );
        
        // Log login history
        const isNewDevice = await checkNewDevice(user.id, req.ip, deviceInfo);
        await db.query(
            'INSERT INTO login_history (user_id, ip_address, user_agent, device_info, is_new_device) VALUES (?, ?, ?, ?, ?)',
            [user.id, req.ip, req.get('User-Agent'), deviceInfo, isNewDevice]
        );
        
        // Update last login
        await db.query('UPDATE users SET last_login = NOW(), ip_address = ? WHERE id = ?', [req.ip, user.id]);
        
        // Send new device alert
        if (isNewDevice) {
            await sendNewDeviceAlert(user.email, deviceInfo, req.ip);
        }
        
        const { password: _, ...userData } = user;
        res.json({ 
            message: 'Login successful', 
            token, 
            user: userData,
            isNewDevice
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    
    try {
        const [users] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        
        if (users.length > 0) {
            const resetToken = uuidv4();
            await db.query(
                'UPDATE users SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?',
                [resetToken, users[0].id]
            );
            
            // Send reset email
            await sendPasswordResetEmail(email, resetToken);
        }
        
        res.json({ message: 'If the email exists, a reset link has been sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, password } = req.body;
    
    try {
        const [users] = await db.query(
            'SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
            [token]
        );
        
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        await db.query(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
            [hashedPassword, users[0].id]
        );
        
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND token = ?', 
            [req.user.id, req.headers.authorization.split(' ')[1]]);
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    const { password, ...userData } = req.user;
    res.json({ user: userData });
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/users/:identifier', authenticateToken, async (req, res) => {
    const { identifier } = req.params;
    
    try {
        let query = 'SELECT id, username, email, fullname, bio, profile_pic, cover_photo, birthdate, birthdate_privacy, verified, role, created_at FROM users WHERE ';
        query += isNaN(identifier) ? 'username = ?' : 'id = ?';
        
        const [users] = await db.query(query, [identifier]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = users[0];
        
        // Get friend count
        const [friendCount] = await db.query(
            'SELECT COUNT(*) as count FROM friends WHERE (user_id = ? OR friend_id = ?) AND status = "accepted"',
            [user.id, user.id]
        );
        
        // Get post count
        const [postCount] = await db.query(
            'SELECT COUNT(*) as count FROM posts WHERE user_id = ? AND deleted_at IS NULL',
            [user.id]
        );
        
        // Check friendship status
        const [friendship] = await db.query(
            'SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
            [req.user.id, user.id, user.id, req.user.id]
        );
        
        // Get mutual friends
        const [mutualFriends] = await db.query(
            `SELECT u.id, u.username, u.fullname, u.profile_pic 
             FROM friends f1 
             JOIN friends f2 ON f1.friend_id = f2.friend_id 
             JOIN users u ON u.id = f1.friend_id 
             WHERE f1.user_id = ? AND f2.user_id = ? AND f1.status = 'accepted' AND f2.status = 'accepted'
             LIMIT 10`,
            [req.user.id, user.id]
        );
        
        res.json({
            ...user,
            friendCount: friendCount[0].count,
            postCount: postCount[0].count,
            friendshipStatus: friendship[0]?.status || 'none',
            isOwnProfile: req.user.id === user.id,
            mutualFriends
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update profile
app.put('/api/users/profile', authenticateToken, upload.single('profile_pic'), async (req, res) => {
    const { fullname, bio, birthdate, birthdate_privacy } = req.body;
    const profilePic = req.file ? `/uploads/profiles/${req.file.filename}` : null;
    
    try {
        const updateFields = [];
        const values = [];
        
        if (fullname) { updateFields.push('fullname = ?'); values.push(fullname); }
        if (bio !== undefined) { updateFields.push('bio = ?'); values.push(bio); }
        if (birthdate) { updateFields.push('birthdate = ?'); values.push(birthdate); }
        if (birthdate_privacy) { updateFields.push('birthdate_privacy = ?'); values.push(birthdate_privacy); }
        if (profilePic) { updateFields.push('profile_pic = ?'); values.push(profilePic); }
        
        values.push(req.user.id);
        
        await db.query(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, values);
        
        res.json({ message: 'Profile updated', profilePic });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Search users
app.get('/api/users/search/:query', authenticateToken, async (req, res) => {
    const { query } = req.params;
    
    try {
        const [users] = await db.query(
            `SELECT id, username, fullname, profile_pic, verified 
             FROM users 
             WHERE (username LIKE ? OR fullname LIKE ?) AND id != ? AND is_banned = FALSE 
             ORDER BY verified DESC, username 
             LIMIT 20`,
            [`%${query}%`, `%${query}%`, req.user.id]
        );
        
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Generate QR code for profile
app.get('/api/users/:id/qrcode', authenticateToken, async (req, res) => {
    try {
        const profileUrl = `${req.protocol}://${req.get('host')}/profile/${req.params.id}`;
        const qrDataUrl = await QRCode.toDataURL(profileUrl);
        
        res.json({ qrCode: qrDataUrl, profileUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// ==================== FRIEND ROUTES ====================

// Send friend request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    
    if (friendId === req.user.id) {
        return res.status(400).json({ error: 'Cannot add yourself' });
    }
    
    try {
        // Check privacy settings
        const [targetUser] = await db.query('SELECT privacy_settings FROM users WHERE id = ?', [friendId]);
        
        if (targetUser.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const privacy = JSON.parse(targetUser[0].privacy_settings || '{}');
        
        // Check if already friends or pending
        const [existing] = await db.query(
            'SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
            [req.user.id, friendId, friendId, req.user.id]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Friend request already exists' });
        }
        
        // Insert friend request
        await db.query(
            'INSERT INTO friends (user_id, friend_id, requester_id, status) VALUES (?, ?, ?, "pending")',
            [req.user.id, friendId, req.user.id]
        );
        
        // Create notification
        await createNotification(friendId, 'friend_request', req.user.id, 'user', 
            `${req.user.fullname} sent you a friend request`);
        
        // Emit real-time notification
        io.to(`user_${friendId}`).emit('notification', {
            type: 'friend_request',
            from: { id: req.user.id, fullname: req.user.fullname, profile_pic: req.user.profile_pic }
        });
        
        res.json({ message: 'Friend request sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

// Accept/Reject friend request
app.post('/api/friends/respond', authenticateToken, async (req, res) => {
    const { requestId, action } = req.body; // action: 'accept' or 'reject'
    
    try {
        const [requests] = await db.query(
            'SELECT * FROM friends WHERE id = ? AND friend_id = ? AND status = "pending"',
            [requestId, req.user.id]
        );
        
        if (requests.length === 0) {
            return res.status(404).json({ error: 'Friend request not found' });
        }
        
        const request = requests[0];
        
        if (action === 'accept') {
            await db.query('UPDATE friends SET status = "accepted" WHERE id = ?', [requestId]);
            
            // Add reverse friendship
            await db.query(
                'INSERT INTO friends (user_id, friend_id, requester_id, status) VALUES (?, ?, ?, "accepted")',
                [req.user.id, request.user_id, request.user_id]
            );
            
            // Create notification
            await createNotification(request.user_id, 'friend_accepted', req.user.id, 'user',
                `${req.user.fullname} accepted your friend request`);
            
            io.to(`user_${request.user_id}`).emit('notification', {
                type: 'friend_accepted',
                from: { id: req.user.id, fullname: req.user.fullname }
            });
        } else {
            await db.query('DELETE FROM friends WHERE id = ?', [requestId]);
        }
        
        res.json({ message: `Friend request ${action}ed` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to respond to friend request' });
    }
});

// Get friends list
app.get('/api/friends/:userId?', authenticateToken, async (req, res) => {
    const userId = req.params.userId || req.user.id;
    
    try {
        const [friends] = await db.query(
            `SELECT u.id, u.username, u.fullname, u.profile_pic, u.verified 
             FROM friends f 
             JOIN users u ON (u.id = f.friend_id OR u.id = f.user_id) 
             WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'accepted' AND u.id != ?
             ORDER BY u.fullname`,
            [userId, userId, userId]
        );
        
        res.json(friends);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch friends' });
    }
});

// Get friend requests
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const [requests] = await db.query(
            `SELECT f.id, u.id as user_id, u.username, u.fullname, u.profile_pic, u.verified, f.created_at 
             FROM friends f 
             JOIN users u ON u.id = f.user_id 
             WHERE f.friend_id = ? AND f.status = 'pending'
             ORDER BY f.created_at DESC`,
            [req.user.id]
        );
        
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch friend requests' });
    }
});

// Remove friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
    const { friendId } = req.params;
    
    try {
        await db.query(
            'DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
            [req.user.id, friendId, friendId, req.user.id]
        );
        
        res.json({ message: 'Friend removed' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove friend' });
    }
});

// Block user
app.post('/api/friends/block/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    
    try {
        await db.query(
            'INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, "blocked") ON DUPLICATE KEY UPDATE status = "blocked"',
            [req.user.id, userId]
        );
        
        res.json({ message: 'User blocked' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to block user' });
    }
});

// ==================== POST ROUTES ====================

// Create post
app.post('/api/posts', authenticateToken, upload.array('media', 5), async (req, res) => {
    const { content, privacy, taggedUsers } = req.body;
    const files = req.files;
    
    try {
        const mediaUrls = files ? files.map(f => `/uploads/posts/${f.filename}`) : [];
        const postType = mediaUrls.length > 0 ? 'image' : 'text';
        const taggedUsersArray = taggedUsers ? JSON.parse(taggedUsers) : [];
        
        const [result] = await db.query(
            `INSERT INTO posts (user_id, content, post_type, media_urls, privacy, tagged_users) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, content, postType, JSON.stringify(mediaUrls), privacy || 'friends', JSON.stringify(taggedUsersArray)]
        );
        
        // Notify tagged users
        for (const taggedId of taggedUsersArray) {
            await createNotification(taggedId, 'mention', result.insertId, 'post',
                `${req.user.fullname} mentioned you in a post`);
            io.to(`user_${taggedId}`).emit('notification', { type: 'mention', postId: result.insertId });
        }
        
        // Get the created post with user info
        const [posts] = await db.query(
            `SELECT p.*, u.id as user_id, u.username, u.fullname, u.profile_pic, u.verified 
             FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?`,
            [result.insertId]
        );
        
        const post = { ...posts[0], reactions: {}, reactionCount: 0, commentCount: 0, isLiked: false };
        
        io.emit('new_post', post);
        res.status(201).json(post);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Get feed
app.get('/api/posts/feed', authenticateToken, async (req, res) => {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    try {
        // Get friend IDs
        const [friends] = await db.query(
            'SELECT friend_id FROM friends WHERE user_id = ? AND status = "accepted"',
            [req.user.id]
        );
        const friendIds = friends.map(f => f.friend_id);
        friendIds.push(req.user.id);
        
        const [posts] = await db.query(
            `SELECT p.*, u.id as user_id, u.username, u.fullname, u.profile_pic, u.verified,
                    (SELECT COUNT(*) FROM reactions WHERE target_id = p.id AND target_type = 'post') as reaction_count,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND deleted_at IS NULL) as comment_count,
                    (SELECT reaction_type FROM reactions WHERE target_id = p.id AND user_id = ? LIMIT 1) as user_reaction
             FROM posts p 
             JOIN users u ON p.user_id = u.id 
             WHERE p.user_id IN (?) AND p.deleted_at IS NULL AND p.group_id IS NULL
             ORDER BY p.is_trending DESC, p.created_at DESC 
             LIMIT ? OFFSET ?`,
            [req.user.id, friendIds, parseInt(limit), offset]
        );
        
        // Get reaction breakdown for each post
        for (const post of posts) {
            const [reactions] = await db.query(
                'SELECT reaction_type, COUNT(*) as count FROM reactions WHERE target_id = ? AND target_type = "post" GROUP BY reaction_type',
                [post.id]
            );
            post.reactions = reactions.reduce((acc, r) => ({ ...acc, [r.reaction_type]: r.count }), {});
            post.media_urls = post.media_urls ? JSON.parse(post.media_urls) : [];
            post.tagged_users = post.tagged_users ? JSON.parse(post.tagged_users) : [];
        }
        
        res.json(posts);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch feed' });
    }
});

// Get trending posts
app.get('/api/posts/trending', authenticateToken, async (req, res) => {
    try {
        const [posts] = await db.query(
            `SELECT p.*, u.id as user_id, u.username, u.fullname, u.profile_pic, u.verified,
                    (SELECT COUNT(*) FROM reactions WHERE target_id = p.id AND target_type = 'post') as reaction_count,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
             FROM posts p 
             JOIN users u ON p.user_id = u.id 
             WHERE p.privacy = 'public' AND p.deleted_at IS NULL AND p.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
             ORDER BY reaction_count + comment_count * 2 DESC 
             LIMIT 10`
        );
        
        res.json(posts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch trending posts' });
    }
});

// Get single post
app.get('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const [posts] = await db.query(
            `SELECT p.*, u.id as user_id, u.username, u.fullname, u.profile_pic, u.verified,
                    (SELECT reaction_type FROM reactions WHERE target_id = p.id AND user_id = ? LIMIT 1) as user_reaction
             FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?`,
            [req.user.id, req.params.id]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }
        
        // Get comments
        const [comments] = await db.query(
            `SELECT c.*, u.username, u.fullname, u.profile_pic 
             FROM comments c JOIN users u ON c.user_id = u.id 
             WHERE c.post_id = ? AND c.deleted_at IS NULL 
             ORDER BY c.created_at ASC`,
            [req.params.id]
        );
        
        const post = posts[0];
        post.media_urls = post.media_urls ? JSON.parse(post.media_urls) : [];
        post.comments = comments;
        
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch post' });
    }
});

// React to post
app.post('/api/posts/:id/react', authenticateToken, async (req, res) => {
    const { reactionType } = req.body;
    
    try {
        // Check existing reaction
        const [existing] = await db.query(
            'SELECT * FROM reactions WHERE user_id = ? AND target_id = ? AND target_type = "post"',
            [req.user.id, req.params.id]
        );
        
        if (existing.length > 0) {
            if (existing[0].reaction_type === reactionType) {
                // Remove reaction
                await db.query('DELETE FROM reactions WHERE id = ?', [existing[0].id]);
            } else {
                // Update reaction
                await db.query('UPDATE reactions SET reaction_type = ? WHERE id = ?', [reactionType, existing[0].id]);
            }
        } else {
            // Add new reaction
            await db.query(
                'INSERT INTO reactions (user_id, target_id, target_type, reaction_type) VALUES (?, ?, "post", ?)',
                [req.user.id, req.params.id, reactionType]
            );
            
            // Get post owner
            const [posts] = await db.query('SELECT user_id FROM posts WHERE id = ?', [req.params.id]);
            if (posts.length > 0 && posts[0].user_id !== req.user.id) {
                await createNotification(posts[0].user_id, 'like', req.params.id, 'post',
                    `${req.user.fullname} reacted to your post`);
                io.to(`user_${posts[0].user_id}`).emit('notification', { type: 'like', postId: req.params.id });
            }
        }
        
        // Get updated reaction counts
        const [reactions] = await db.query(
            'SELECT reaction_type, COUNT(*) as count FROM reactions WHERE target_id = ? AND target_type = "post" GROUP BY reaction_type',
            [req.params.id]
        );
        
        const reactionCounts = reactions.reduce((acc, r) => ({ ...acc, [r.reaction_type]: r.count }), {});
        
        io.emit('post_reaction', { postId: req.params.id, reactions: reactionCounts });
        res.json({ reactions: reactionCounts });
    } catch (error) {
        res.status(500).json({ error: 'Failed to react' });
    }
});

// Add comment
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    const { content, parentId } = req.body;
    
    try {
        const [result] = await db.query(
            'INSERT INTO comments (post_id, user_id, parent_id, content) VALUES (?, ?, ?, ?)',
            [req.params.id, req.user.id, parentId || null, content]
        );
        
        // Get post owner
        const [posts] = await db.query('SELECT user_id FROM posts WHERE id = ?', [req.params.id]);
        
        if (posts.length > 0 && posts[0].user_id !== req.user.id) {
            await createNotification(posts[0].user_id, 'comment', req.params.id, 'post',
                `${req.user.fullname} commented on your post`);
            io.to(`user_${posts[0].user_id}`).emit('notification', { type: 'comment', postId: req.params.id });
        }
        
        const [comments] = await db.query(
            'SELECT c.*, u.username, u.fullname, u.profile_pic FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?',
            [result.insertId]
        );
        
        io.emit('new_comment', { postId: req.params.id, comment: comments[0] });
        res.status(201).json(comments[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const [posts] = await db.query('SELECT user_id FROM posts WHERE id = ?', [req.params.id]);
        
        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }
        
        if (posts[0].user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        await db.query('UPDATE posts SET deleted_at = NOW() WHERE id = ?', [req.params.id]);
        
        res.json({ message: 'Post deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// Share post
app.post('/api/posts/:id/share', authenticateToken, async (req, res) => {
    try {
        const [result] = await db.query(
            'INSERT INTO posts (user_id, content, post_type, shared_from, privacy) VALUES (?, ?, "shared", ?, ?)',
            [req.user.id, req.body.content || '', req.params.id, req.body.privacy || 'friends']
        );
        
        res.status(201).json({ message: 'Post shared', postId: result.insertId });
    } catch (error) {
        res.status(500).json({ error: 'Failed to share post' });
    }
});

// Save post
app.post('/api/posts/:id/save', authenticateToken, async (req, res) => {
    try {
        await db.query(
            'INSERT INTO saved_posts (user_id, post_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id',
            [req.user.id, req.params.id]
        );
        
        res.json({ message: 'Post saved' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save post' });
    }
});

// ==================== CHAT ROUTES ====================

// Get user chats
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const [chats] = await db.query(
            `SELECT c.*, 
                    (SELECT content FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
                    (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_time,
                    (SELECT COUNT(*) FROM messages WHERE chat_id = c.id AND JSON_CONTAINS(read_by, CAST(? AS JSON)) = 0) as unread_count
             FROM chats c 
             JOIN chat_members cm ON c.id = cm.chat_id 
             WHERE cm.user_id = ? 
             ORDER BY last_message_time DESC`,
            [req.user.id.toString(), req.user.id]
        );
        
        // For private chats, get the other user's info
        for (const chat of chats) {
            if (chat.chat_type === 'private') {
                const [members] = await db.query(
                    `SELECT u.id, u.username, u.fullname, u.profile_pic, u.verified 
                     FROM chat_members cm JOIN users u ON cm.user_id = u.id 
                     WHERE cm.chat_id = ? AND cm.user_id != ?`,
                    [chat.id, req.user.id]
                );
                chat.recipient = members[0];
            }
        }
        
        res.json(chats);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

// Get or create private chat
app.post('/api/chats/private', authenticateToken, async (req, res) => {
    const { recipientId } = req.body;
    
    try {
        // Check existing chat
        const [existing] = await db.query(
            `SELECT c.* FROM chats c 
             JOIN chat_members cm1 ON c.id = cm1.chat_id 
             JOIN chat_members cm2 ON c.id = cm2.chat_id 
             WHERE c.chat_type = 'private' AND cm1.user_id = ? AND cm2.user_id = ?`,
            [req.user.id, recipientId]
        );
        
        if (existing.length > 0) {
            return res.json(existing[0]);
        }
        
        // Create new chat
        const [result] = await db.query('INSERT INTO chats (chat_type) VALUES ("private")');
        
        await db.query('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?), (?, ?)',
            [result.insertId, req.user.id, result.insertId, recipientId]);
        
        const [chats] = await db.query('SELECT * FROM chats WHERE id = ?', [result.insertId]);
        
        res.status(201).json(chats[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get chat messages
app.get('/api/chats/:id/messages', authenticateToken, async (req, res) => {
    const { page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    
    try {
        const [messages] = await db.query(
            `SELECT m.*, u.id as sender_id, u.username, u.fullname, u.profile_pic 
             FROM messages m 
             JOIN users u ON m.sender_id = u.id 
             WHERE m.chat_id = ? 
             ORDER BY m.created_at DESC 
             LIMIT ? OFFSET ?`,
            [req.params.id, parseInt(limit), offset]
        );
        
        res.json(messages.reverse());
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// Send message
app.post('/api/chats/:id/messages', authenticateToken, async (req, res) => {
    const { content, type, mediaUrl } = req.body;
    
    try {
        const [result] = await db.query(
            'INSERT INTO messages (chat_id, sender_id, content, message_type, media_url, read_by) VALUES (?, ?, ?, ?, ?, ?)',
            [req.params.id, req.user.id, content, type || 'text', mediaUrl, JSON.stringify([req.user.id])]
        );
        
        const [messages] = await db.query(
            'SELECT m.*, u.username, u.fullname, u.profile_pic FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?',
            [result.insertId]
        );
        
        const message = messages[0];
        
        // Get chat members
        const [members] = await db.query('SELECT user_id FROM chat_members WHERE chat_id = ?', [req.params.id]);
        
        // Emit to all chat members
        members.forEach(member => {
            io.to(`user_${member.user_id}`).emit('new_message', { chatId: req.params.id, message });
        });
        
        res.status(201).json(message);
    } catch (error) {
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Mark messages as read
app.post('/api/chats/:id/read', authenticateToken, async (req, res) => {
    try {
        await db.query(
            `UPDATE messages SET read_by = JSON_ARRAY_APPEND(read_by, '$', ?) 
             WHERE chat_id = ? AND JSON_CONTAINS(read_by, CAST(? AS JSON)) = 0`,
            [req.user.id, req.params.id, req.user.id.toString()]
        );
        
        io.to(`chat_${req.params.id}`).emit('messages_read', { chatId: req.params.id, userId: req.user.id });
        
        res.json({ message: 'Messages marked as read' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

// Delete message
app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        const [messages] = await db.query('SELECT sender_id, chat_id FROM messages WHERE id = ?', [req.params.id]);
        
        if (messages.length === 0 || messages[0].sender_id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        await db.query('DELETE FROM messages WHERE id = ?', [req.params.id]);
        
        io.to(`chat_${messages[0].chat_id}`).emit('message_deleted', { messageId: req.params.id });
        
        res.json({ message: 'Message deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// ==================== GROUP ROUTES ====================

// Create group
app.post('/api/groups', authenticateToken, upload.single('cover'), async (req, res) => {
    const { name, description, privacy } = req.body;
    const coverPhoto = req.file ? `/uploads/groups/${req.file.filename}` : null;
    
    try {
        const [result] = await db.query(
            'INSERT INTO groups (name, description, privacy, cover_photo, created_by) VALUES (?, ?, ?, ?, ?)',
            [name, description, privacy || 'open', coverPhoto, req.user.id]
        );
        
        // Add creator as admin
        await db.query(
            'INSERT INTO group_members (group_id, user_id, role, status) VALUES (?, ?, "admin", "approved")',
            [result.insertId, req.user.id]
        );
        
        res.status(201).json({ message: 'Group created', groupId: result.insertId });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create group' });
    }
});

// Get groups
app.get('/api/groups', authenticateToken, async (req, res) => {
    try {
        const [groups] = await db.query(
            `SELECT g.*, u.username as creator_name,
                    (SELECT COUNT(*) FROM group_members WHERE group_id = g.id AND status = 'approved') as member_count
             FROM groups g 
             JOIN users u ON g.created_by = u.id 
             WHERE g.privacy = 'open' OR g.id IN (SELECT group_id FROM group_members WHERE user_id = ?)
             ORDER BY g.created_at DESC`,
            [req.user.id]
        );
        
        res.json(groups);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch groups' });
    }
});

// Join group
app.post('/api/groups/:id/join', authenticateToken, async (req, res) => {
    try {
        const [groups] = await db.query('SELECT privacy FROM groups WHERE id = ?', [req.params.id]);
        
        if (groups.length === 0) {
            return res.status(404).json({ error: 'Group not found' });
        }
        
        const status = groups[0].privacy === 'open' ? 'approved' : 'pending';
        
        await db.query(
            'INSERT INTO group_members (group_id, user_id, status) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE status = ?',
            [req.params.id, req.user.id, status, status]
        );
        
        res.json({ message: status === 'approved' ? 'Joined group' : 'Request sent', status });
    } catch (error) {
        res.status(500).json({ error: 'Failed to join group' });
    }
});

// Get group posts
app.get('/api/groups/:id/posts', authenticateToken, async (req, res) => {
    try {
        const [posts] = await db.query(
            `SELECT p.*, u.username, u.fullname, u.profile_pic, u.verified 
             FROM posts p JOIN users u ON p.user_id = u.id 
             WHERE p.group_id = ? AND p.deleted_at IS NULL 
             ORDER BY p.created_at DESC`,
            [req.params.id]
        );
        
        res.json(posts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch group posts' });
    }
});

// ==================== NOTIFICATION ROUTES ====================

// Get notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    const { page = 1, limit = 30 } = req.query;
    const offset = (page - 1) * limit;
    
    try {
        const [notifications] = await db.query(
            `SELECT n.*, u.username, u.fullname, u.profile_pic 
             FROM notifications n 
             LEFT JOIN users u ON n.reference_id = u.id 
             WHERE n.user_id = ? 
             ORDER BY n.created_at DESC 
             LIMIT ? OFFSET ?`,
            [req.user.id, parseInt(limit), offset]
        );
        
        res.json(notifications);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// Mark notifications as read
app.post('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE notifications SET is_read = TRUE WHERE user_id = ?', [req.user.id]);
        res.json({ message: 'Notifications marked as read' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

// ==================== BIRTHDAY ROUTES ====================

// Get today's birthdays
app.get('/api/birthdays/today', authenticateToken, async (req, res) => {
    try {
        const [birthdays] = await db.query(
            `SELECT u.id, u.username, u.fullname, u.profile_pic 
             FROM users u 
             JOIN friends f ON (f.user_id = u.id OR f.friend_id = u.id) 
             WHERE f.status = 'accepted' 
             AND (f.user_id = ? OR f.friend_id = ?) 
             AND u.id != ? 
             AND MONTH(u.birthdate) = MONTH(CURDATE()) 
             AND DAY(u.birthdate) = DAY(CURDATE()) 
             AND u.birthdate_privacy != 'private'
             GROUP BY u.id`,
            [req.user.id, req.user.id, req.user.id]
        );
        
        res.json(birthdays);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch birthdays' });
    }
});

// Send birthday wish
app.post('/api/birthdays/wish', authenticateToken, async (req, res) => {
    const { recipientId, message, giftType } = req.body;
    
    try {
        const [result] = await db.query(
            'INSERT INTO birthday_wishes (sender_id, recipient_id, message, gift_type) VALUES (?, ?, ?, ?)',
            [req.user.id, recipientId, message, giftType]
        );
        
        await createNotification(recipientId, 'birthday', req.user.id, 'user',
            `${req.user.fullname} sent you a birthday wish!`);
        
        res.status(201).json({ message: 'Birthday wish sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send birthday wish' });
    }
});

// ==================== ADMIN ROUTES ====================

// Get flagged accounts
app.get('/api/admin/flagged', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [flagged] = await db.query(
            `SELECT u.id, u.username, u.email, u.fullname, u.profile_pic, u.created_at, 
                    ff.risk_score, ff.flag_reason 
             FROM users u 
             JOIN fake_flags ff ON u.id = ff.user_id 
             WHERE ff.reviewed = FALSE 
             ORDER BY ff.risk_score DESC`
        );
        
        res.json(flagged);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch flagged accounts' });
    }
});

// Ban user
app.post('/api/admin/ban/:userId', authenticateToken, requireAdmin, async (req, res) => {
    const { reason } = req.body;
    
    try {
        await db.query('UPDATE users SET is_banned = TRUE, ban_reason = ? WHERE id = ?', [reason, req.params.userId]);
        
        await logAdminAction(req.user.id, 'ban_user', 'user', req.params.userId, { reason });
        
        res.json({ message: 'User banned' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

// Verify user
app.post('/api/admin/verify/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await db.query('UPDATE users SET verified = TRUE, verification_requested = FALSE WHERE id = ?', [req.params.userId]);
        
        await logAdminAction(req.user.id, 'verify_user', 'user', req.params.userId);
        
        res.json({ message: 'User verified' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to verify user' });
    }
});

// Get reports
app.get('/api/admin/reports', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [reports] = await db.query(
            `SELECT r.*, u.username as reporter_name, u.fullname as reporter_fullname 
             FROM reports r 
             JOIN users u ON r.reporter_id = u.id 
             WHERE r.status = 'pending' 
             ORDER BY r.created_at DESC`
        );
        
        res.json(reports);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Request verification
app.post('/api/users/request-verification', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE users SET verification_requested = TRUE WHERE id = ?', [req.user.id]);
        
        res.json({ message: 'Verification request submitted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit verification request' });
    }
});

// Report content
app.post('/api/reports', authenticateToken, async (req, res) => {
    const { targetId, targetType, reason } = req.body;
    
    try {
        await db.query(
            'INSERT INTO reports (reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?)',
            [req.user.id, targetId, targetType, reason]
        );
        
        res.status(201).json({ message: 'Report submitted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit report' });
    }
});

// ==================== SESSION MANAGEMENT ====================

// Get active sessions
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        const [sessions] = await db.query(
            'SELECT id, device_info, ip_address, last_activity, created_at FROM sessions WHERE user_id = ? AND is_active = TRUE ORDER BY last_activity DESC',
            [req.user.id]
        );
        
        res.json(sessions);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// Logout from other sessions
app.post('/api/sessions/logout-others', authenticateToken, async (req, res) => {
    const currentToken = req.headers.authorization.split(' ')[1];
    
    try {
        await db.query(
            'UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND token != ?',
            [req.user.id, currentToken]
        );
        
        res.json({ message: 'Logged out from other sessions' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to logout from other sessions' });
    }
});

// ==================== SOCKET.IO ====================

const connectedUsers = new Map();

io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) return next(new Error('Authentication required'));
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (error) {
        next(new Error('Invalid token'));
    }
});

io.on('connection', async (socket) => {
    const userId = socket.userId;
    
    // Track connected user
    connectedUsers.set(userId, socket.id);
    socket.join(`user_${userId}`);
    
    // Update online status
    await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [userId]);
    
    // Broadcast online status to friends
    const [friends] = await db.query(
        'SELECT user_id, friend_id FROM friends WHERE (user_id = ? OR friend_id = ?) AND status = "accepted"',
        [userId, userId]
    );
    
    friends.forEach(f => {
        const friendId = f.user_id === userId ? f.friend_id : f.user_id;
        io.to(`user_${friendId}`).emit('user_online', { userId });
    });
    
    console.log(`User ${userId} connected`);
    
    // Handle typing indicator
    socket.on('typing_start', ({ chatId, recipientId }) => {
        io.to(`user_${recipientId}`).emit('user_typing', { chatId, userId });
    });
    
    socket.on('typing_stop', ({ chatId, recipientId }) => {
        io.to(`user_${recipientId}`).emit('user_stopped_typing', { chatId, userId });
    });
    
    // Handle joining chat room
    socket.on('join_chat', (chatId) => {
        socket.join(`chat_${chatId}`);
    });
    
    // Handle disconnect
    socket.on('disconnect', async () => {
        connectedUsers.delete(userId);
        
        // Broadcast offline status
        friends.forEach(f => {
            const friendId = f.user_id === userId ? f.friend_id : f.user_id;
            io.to(`user_${friendId}`).emit('user_offline', { userId });
        });
        
        console.log(`User ${userId} disconnected`);
    });
});

// Check if user is online
app.get('/api/users/:id/online', authenticateToken, (req, res) => {
    const isOnline = connectedUsers.has(parseInt(req.params.id));
    res.json({ online: isOnline });
});

// ==================== HELPER FUNCTIONS ====================

async function createNotification(userId, type, referenceId, referenceType, message, data = null) {
    await db.query(
        'INSERT INTO notifications (user_id, type, reference_id, reference_type, message, data) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, type, referenceId, referenceType, message, JSON.stringify(data)]
    );
}

async function checkFakeAccount(userId, ip, email) {
    let riskScore = 0;
    const reasons = [];
    
    // Check IP
    const [sameIp] = await db.query('SELECT COUNT(*) as count FROM users WHERE ip_address = ?', [ip]);
    if (sameIp[0].count > 3) {
        riskScore += 30;
        reasons.push('Multiple accounts from same IP');
    }
    
    // Check email domain
    const suspiciousDomains = ['tempmail', 'guerrilla', '10minutemail', 'throwaway'];
    if (suspiciousDomains.some(d => email.includes(d))) {
        riskScore += 50;
        reasons.push('Suspicious email domain');
    }
    
    if (riskScore > 0) {
        await db.query(
            'INSERT INTO fake_flags (user_id, flag_reason, risk_score) VALUES (?, ?, ?)',
            [userId, reasons.join(', '), riskScore]
        );
    }
}

async function checkNewDevice(userId, ip, deviceInfo) {
    const [history] = await db.query(
        'SELECT id FROM login_history WHERE user_id = ? AND (ip_address = ? OR device_info = ?)',
        [userId, ip, deviceInfo]
    );
    return history.length === 0;
}

async function sendVerificationEmail(email, otp) {
    // In production, configure your SMTP settings
    console.log(`Verification OTP for ${email}: ${otp}`);
    
    // Uncomment when SMTP is configured
    // await emailTransporter.sendMail({
    //     from: process.env.SMTP_FROM || 'noreply@friendsconnect.com',
    //     to: email,
    //     subject: 'Verify Your Email - FriendsConnect',
    //     html: `<p>Your verification code is: <strong>${otp}</strong></p>`
    // });
}

async function sendPasswordResetEmail(email, token) {
    const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
    console.log(`Password reset link for ${email}: ${resetUrl}`);
    
    // await emailTransporter.sendMail({
    //     from: process.env.SMTP_FROM || 'noreply@friendsconnect.com',
    //     to: email,
    //     subject: 'Reset Your Password - FriendsConnect',
    //     html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`
    // });
}

async function sendNewDeviceAlert(email, deviceInfo, ip) {
    console.log(`New device login alert for ${email} from ${ip}`);
}

async function logAdminAction(adminId, action, targetType, targetId, details = null) {
    await db.query(
        'INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [adminId, action, targetType, targetId, JSON.stringify(details)]
    );
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Serve main app
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
    console.log(`FriendsConnect server running on port ${PORT}`);
});

module.exports = { app, server, io };
