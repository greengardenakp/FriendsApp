// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2');
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
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"] 
    }
});

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'friendsconnect-secret-key-2024';

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'friendsconnect'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to MySQL database');
    }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create uploads directories
const uploadDirs = ['uploads', 'uploads/profiles', 'uploads/posts', 'uploads/messages'];
uploadDirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Multer configuration
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
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|webm/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await db.promise().query(
            'SELECT * FROM users WHERE id = ? AND is_banned = FALSE',
            [decoded.userId]
        );
        
        if (users.length === 0) {
            return res.status(403).json({ error: 'User not found or banned' });
        }
        
        req.user = users[0];
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, fullname, birthdate } = req.body;
    
    try {
        // Check existing user
        const [existing] = await db.promise().query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert user
        const [result] = await db.promise().query(
            'INSERT INTO users (username, email, password, fullname, birthdate) VALUES (?, ?, ?, ?, ?)',
            [username, email, hashedPassword, fullname, birthdate || null]
        );
        
        // Generate OTP (simplified - in production send actual email)
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        console.log(`OTP for ${email}: ${otp}`); // In production, send via email
        
        res.status(201).json({ 
            message: 'Registration successful',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Verify email
app.post('/api/auth/verify-email', async (req, res) => {
    const { email, otp } = req.body;
    
    // Simplified - in production verify OTP from database
    if (otp) {
        await db.promise().query(
            'UPDATE users SET email_verified = TRUE WHERE email = ?',
            [email]
        );
        res.json({ message: 'Email verified successfully' });
    } else {
        res.status(400).json({ error: 'Invalid OTP' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password, deviceInfo } = req.body;
    
    try {
        const [users] = await db.promise().query(
            'SELECT * FROM users WHERE (email = ? OR username = ?) AND is_banned = FALSE',
            [email, email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        
        const { password: _, ...userData } = user;
        res.json({ 
            message: 'Login successful', 
            token, 
            user: userData
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
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
        
        const [users] = await db.promise().query(query, [identifier]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = users[0];
        
        // Get friend count
        const [friendCount] = await db.promise().query(
            'SELECT COUNT(*) as count FROM friendships WHERE (user_id = ? OR friend_id = ?) AND status = "accepted"',
            [user.id, user.id]
        );
        
        // Get post count
        const [postCount] = await db.promise().query(
            'SELECT COUNT(*) as count FROM posts WHERE user_id = ?',
            [user.id]
        );
        
        // Check friendship status
        const [friendship] = await db.promise().query(
            'SELECT * FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
            [req.user.id, user.id, user.id, req.user.id]
        );
        
        res.json({
            ...user,
            friendCount: friendCount[0].count,
            postCount: postCount[0].count,
            friendshipStatus: friendship[0]?.status || 'none',
            isOwnProfile: req.user.id === user.id
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update profile
app.put('/api/users/profile', authenticateToken, upload.single('profile_pic'), async (req, res) => {
    const { fullname, bio, birthdate, birthdate_privacy } = req.body;
    
    try {
        const updateFields = [];
        const values = [];
        
        if (fullname) { updateFields.push('fullname = ?'); values.push(fullname); }
        if (bio !== undefined) { updateFields.push('bio = ?'); values.push(bio); }
        if (birthdate) { updateFields.push('birthdate = ?'); values.push(birthdate); }
        if (birthdate_privacy) { updateFields.push('birthdate_privacy = ?'); values.push(birthdate_privacy); }
        
        values.push(req.user.id);
        
        if (updateFields.length > 0) {
            await db.promise().query(
                `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
                values
            );
        }
        
        res.json({ message: 'Profile updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Search users
app.get('/api/users/search/:query', authenticateToken, async (req, res) => {
    const { query } = req.params;
    
    try {
        const [users] = await db.promise().query(
            `SELECT id, username, fullname, profile_pic, verified 
             FROM users 
             WHERE (username LIKE ? OR fullname LIKE ?) AND id != ? 
             LIMIT 20`,
            [`%${query}%`, `%${query}%`, req.user.id]
        );
        
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Generate QR code
app.get('/api/users/:id/qrcode', authenticateToken, async (req, res) => {
    try {
        const profileUrl = `http://localhost:3000/profile/${req.params.id}`;
        const qrDataUrl = await QRCode.toDataURL(profileUrl);
        res.json({ qrCode: qrDataUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// ==================== FRIEND ROUTES ====================

// Send friend request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    
    try {
        await db.promise().query(
            'INSERT INTO friendships (user_id, friend_id, status, requester_id) VALUES (?, ?, "pending", ?)',
            [req.user.id, friendId, req.user.id]
        );
        
        res.json({ message: 'Friend request sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

// Respond to friend request
app.post('/api/friends/respond', authenticateToken, async (req, res) => {
    const { requestId, action } = req.body;
    
    try {
        if (action === 'accept') {
            await db.promise().query(
                'UPDATE friendships SET status = "accepted" WHERE id = ?',
                [requestId]
            );
        } else {
            await db.promise().query(
                'DELETE FROM friendships WHERE id = ?',
                [requestId]
            );
        }
        
        res.json({ message: `Friend request ${action}ed` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to respond' });
    }
});

// Get friend requests
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const [requests] = await db.promise().query(
            `SELECT f.id, u.id as user_id, u.username, u.fullname, u.profile_pic 
             FROM friendships f 
             JOIN users u ON u.id = f.user_id 
             WHERE f.friend_id = ? AND f.status = 'pending'`,
            [req.user.id]
        );
        
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch requests' });
    }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const [friends] = await db.promise().query(
            `SELECT u.id, u.username, u.fullname, u.profile_pic, u.verified 
             FROM friendships f 
             JOIN users u ON (u.id = f.friend_id OR u.id = f.user_id) 
             WHERE (f.user_id = ? OR f.friend_id = ?) 
             AND f.status = 'accepted' 
             AND u.id != ?`,
            [req.user.id, req.user.id, req.user.id]
        );
        
        res.json(friends);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch friends' });
    }
});

// ==================== POST ROUTES ====================

// Create post
app.post('/api/posts', authenticateToken, upload.array('media', 5), async (req, res) => {
    const { content, privacy, taggedUsers } = req.body;
    const files = req.files || [];
    
    try {
        const mediaUrls = files.map(f => `/uploads/posts/${f.filename}`);
        const taggedUsersArray = taggedUsers ? JSON.parse(taggedUsers) : [];
        
        const [result] = await db.promise().query(
            `INSERT INTO posts (user_id, content, post_type, media_urls, privacy, tagged_users) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, content, files.length > 0 ? 'image' : 'text', 
             JSON.stringify(mediaUrls), privacy || 'friends', JSON.stringify(taggedUsersArray)]
        );
        
        // Get the created post
        const [posts] = await db.promise().query(
            `SELECT p.*, u.username, u.fullname, u.profile_pic, u.verified 
             FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?`,
            [result.insertId]
        );
        
        res.status(201).json(posts[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Get feed
app.get('/api/posts/feed', authenticateToken, async (req, res) => {
    try {
        // Get friend IDs
        const [friends] = await db.promise().query(
            'SELECT friend_id FROM friendships WHERE user_id = ? AND status = "accepted"',
            [req.user.id]
        );
        const friendIds = friends.map(f => f.friend_id);
        friendIds.push(req.user.id);
        
        const [posts] = await db.promise().query(
            `SELECT p.*, u.username, u.fullname, u.profile_pic, u.verified,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
             FROM posts p 
             JOIN users u ON p.user_id = u.id 
             WHERE p.user_id IN (?) 
             ORDER BY p.created_at DESC 
             LIMIT 50`,
            [friendIds]
        );
        
        // Get reaction counts
        for (const post of posts) {
            const [reactions] = await db.promise().query(
                'SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type',
                [post.id]
            );
            post.reactions = reactions.reduce((acc, r) => ({ ...acc, [r.reaction_type]: r.count }), {});
            post.media_urls = post.media_urls ? JSON.parse(post.media_urls) : [];
        }
        
        res.json(posts);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch feed' });
    }
});

// React to post
app.post('/api/posts/:id/react', authenticateToken, async (req, res) => {
    const { reactionType } = req.body;
    
    try {
        // Check existing reaction
        const [existing] = await db.promise().query(
            'SELECT * FROM reactions WHERE user_id = ? AND post_id = ?',
            [req.user.id, req.params.id]
        );
        
        if (existing.length > 0) {
            if (existing[0].reaction_type === reactionType) {
                await db.promise().query('DELETE FROM reactions WHERE id = ?', [existing[0].id]);
            } else {
                await db.promise().query(
                    'UPDATE reactions SET reaction_type = ? WHERE id = ?',
                    [reactionType, existing[0].id]
                );
            }
        } else {
            await db.promise().query(
                'INSERT INTO reactions (user_id, post_id, reaction_type) VALUES (?, ?, ?)',
                [req.user.id, req.params.id, reactionType]
            );
        }
        
        // Get updated reaction counts
        const [reactions] = await db.promise().query(
            'SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type',
            [req.params.id]
        );
        
        const reactionCounts = reactions.reduce((acc, r) => ({ ...acc, [r.reaction_type]: r.count }), {});
        res.json({ reactions: reactionCounts });
    } catch (error) {
        res.status(500).json({ error: 'Failed to react' });
    }
});

// Add comment
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    const { content } = req.body;
    
    try {
        const [result] = await db.promise().query(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [req.params.id, req.user.id, content]
        );
        
        const [comments] = await db.promise().query(
            'SELECT c.*, u.username, u.fullname, u.profile_pic FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?',
            [result.insertId]
        );
        
        res.status(201).json(comments[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Get single post with comments
app.get('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const [posts] = await db.promise().query(
            'SELECT * FROM posts WHERE id = ?',
            [req.params.id]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }
        
        const [comments] = await db.promise().query(
            `SELECT c.*, u.username, u.fullname, u.profile_pic 
             FROM comments c JOIN users u ON c.user_id = u.id 
             WHERE c.post_id = ? 
             ORDER BY c.created_at ASC`,
            [req.params.id]
        );
        
        const post = posts[0];
        post.comments = comments;
        post.media_urls = post.media_urls ? JSON.parse(post.media_urls) : [];
        
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch post' });
    }
});

// ==================== CHAT ROUTES ====================

// Get chats
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const [chats] = await db.promise().query(
            `SELECT c.*, 
                    (SELECT content FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
                    (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_time
             FROM chats c 
             JOIN chat_members cm ON c.id = cm.chat_id 
             WHERE cm.user_id = ? 
             ORDER BY last_message_time DESC`,
            [req.user.id]
        );
        
        // Get recipient info for private chats
        for (const chat of chats) {
            if (chat.chat_type === 'private') {
                const [members] = await db.promise().query(
                    `SELECT u.id, u.username, u.fullname, u.profile_pic 
                     FROM chat_members cm JOIN users u ON cm.user_id = u.id 
                     WHERE cm.chat_id = ? AND cm.user_id != ?`,
                    [chat.id, req.user.id]
                );
                chat.recipient = members[0];
            }
        }
        
        res.json(chats);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

// Send message
app.post('/api/chats/:id/messages', authenticateToken, async (req, res) => {
    const { content } = req.body;
    
    try {
        const [result] = await db.promise().query(
            'INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)',
            [req.params.id, req.user.id, content]
        );
        
        const [messages] = await db.promise().query(
            'SELECT m.*, u.username, u.fullname, u.profile_pic FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?',
            [result.insertId]
        );
        
        res.status(201).json(messages[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Get chat messages
app.get('/api/chats/:id/messages', authenticateToken, async (req, res) => {
    try {
        const [messages] = await db.promise().query(
            `SELECT m.*, u.username, u.fullname, u.profile_pic 
             FROM messages m 
             JOIN users u ON m.sender_id = u.id 
             WHERE m.chat_id = ? 
             ORDER BY m.created_at ASC`,
            [req.params.id]
        );
        
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// ==================== NOTIFICATION ROUTES ====================

// Get notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const [notifications] = await db.promise().query(
            `SELECT n.*, u.username, u.fullname, u.profile_pic 
             FROM notifications n 
             LEFT JOIN users u ON n.sender_id = u.id 
             WHERE n.user_id = ? 
             ORDER BY n.created_at DESC 
             LIMIT 50`,
            [req.user.id]
        );
        
        res.json(notifications);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// ==================== BIRTHDAY ROUTES ====================

// Get today's birthdays
app.get('/api/birthdays/today', authenticateToken, async (req, res) => {
    try {
        const [birthdays] = await db.promise().query(
            `SELECT u.id, u.username, u.fullname, u.profile_pic 
             FROM users u 
             WHERE MONTH(u.birthdate) = MONTH(CURDATE()) 
             AND DAY(u.birthdate) = DAY(CURDATE()) 
             AND u.birthdate_privacy != 'private'
             AND u.id != ?`,
            [req.user.id]
        );
        
        res.json(birthdays);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch birthdays' });
    }
});

// ==================== SOCKET.IO ====================

io.use((socket, next) => {
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

io.on('connection', (socket) => {
    console.log(`User ${socket.userId} connected`);
    
    socket.on('join_chat', (chatId) => {
        socket.join(`chat_${chatId}`);
    });
    
    socket.on('typing_start', ({ chatId, recipientId }) => {
        socket.to(`user_${recipientId}`).emit('user_typing', { chatId, userId: socket.userId });
    });
    
    socket.on('typing_stop', ({ chatId, recipientId }) => {
        socket.to(`user_${recipientId}`).emit('user_stopped_typing', { chatId, userId: socket.userId });
    });
    
    socket.on('disconnect', () => {
        console.log(`User ${socket.userId} disconnected`);
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`FriendsConnect server running on port ${PORT}`);
    console.log(`API URL: http://localhost:${PORT}/api`);
});
