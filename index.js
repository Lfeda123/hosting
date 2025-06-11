process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection:', reason);
});

// بداية التطبيق
console.log('Starting application...');

const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const { EmbedBuilder } = require('discord.js');
// Rest of requires
console.log('Loading environment variables...');
require("dotenv").config();
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const { spawn, execSync, exec } = require('child_process');
const Discord = require("discord.js");
const axios = require('axios');
const webhooksDB = path.join(__dirname, 'webhooks.json');

// التأكد من وجود ملف webhooks.json
if (!fs.existsSync(webhooksDB)) {
    fs.writeFileSync(webhooksDB, '{}', 'utf8');
}

// وظيفة لإرسال إشعارات الويبهوك
async function sendWebhookNotification(userId, serverName, eventType, eventData) {
    try {
        // قراءة بيانات الويبهوك
        const webhooksData = JSON.parse(fs.readFileSync(webhooksDB, 'utf8'));
        
        // البحث عن الويبهوك المناسب
        const userWebhooks = webhooksData[userId];
        if (!userWebhooks || !userWebhooks[serverName]) return;
        
        const webhookUrl = userWebhooks[serverName];
        if (!webhookUrl) return;
        
        // تجهيز الرسالة حسب نوع الحدث
        let message = {
            username: "BotHoster Notifications",
            avatar_url: "https://i.imgur.com/4M34hi2.png", // يمكن تغييره لشعار تطبيقك
            embeds: [{
                title: `${eventType}`,
                description: `حدث تم تسجيله في سيرفر: ${serverName}`,
                color: getColorForEvent(eventType),
                fields: [],
                timestamp: new Date()
            }]
        };
        
        // إضافة تفاصيل الحدث
        if (eventData) {
            for (const [key, value] of Object.entries(eventData)) {
                message.embeds[0].fields.push({
                    name: key,
                    value: String(value).slice(0, 1024), // تقييد الطول لتجنب أخطاء Discord
                    inline: true
                });
            }
        }
        
        // إرسال الإشعار
        await axios.post(webhookUrl, message);
        console.log(`Webhook notification sent for ${serverName} (${eventType})`);
    } catch (error) {
        console.error('Error sending webhook notification:', error.message);
    }
}

// وظيفة تحديد لون مناسب لنوع الحدث
function getColorForEvent(eventType) {
    const colors = {
        'تعديل ملف': 0x3498db,      // أزرق
        'إنشاء ملف': 0x2ecc71,      // أخضر
        'حذف ملف': 0xe74c3c,        // أحمر
        'تشغيل السيرفر': 0x27ae60,  // أخضر غامق
        'إيقاف السيرفر': 0xc0392b,  // أحمر غامق
        'نسخ احتياطي': 0xf39c12,    // برتقالي
        'خطأ': 0xe74c3c,            // أحمر
        'تحذير': 0xf1c40f,          // أصفر
        'معلومة': 0x3498db,         // أزرق
        'تسجيل دخول': 0x9b59b6,     // بنفسجي
        'تحديث الإعدادات': 0x1abc9c // فيروزي
    };
    
    return colors[eventType] || 0x7289da; // لون Discord الافتراضي إذا لم يتم العثور على لون مخصص
}


const PORT = 21163; // ثابت على البورت 3000
console.log(`Port configured: ${PORT} (fixed)`);

// منع تغيير البورت لأي سبب
process.env.PORT = PORT;

// إعداد multer للتحميل
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (!req.user) {
            return cb(new Error('User not authenticated'));
        }
        const userId = req.user.id;
        const uploadPath = path.join(__dirname, 'uploads', userId);
        fs.ensureDirSync(uploadPath);
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const originalname = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${Date.now()}-${originalname}`);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' ||
            file.mimetype === 'application/x-zip-compressed' ||
            file.originalname.toLowerCase().endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('يُسمح فقط بملفات ZIP'));
        }
    },
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    }
});

// إعدادات Express الأساسية
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Add health check endpoint with logging
app.get('/health', (req, res) => {
    console.log('Health check endpoint called');
    res.json({
        status: 'ok',
        startup: {
            server: true,
            mongo: mongoose.connection.readyState === 1,
            discord: client?.user?.tag || false
        }
    });
});

// Main storage maps
const processes = new Map();
const serverStats = new Map();
const clients = new Map();

// Discord Bot Configuration
console.log('Configuring Discord bot...');
const client = new Discord.Client({ 
    intents: 3276799,
    // إضافة خيارات لمعالجة أخطاء فشل الاستجابة من Discord API
    rest: {
        timeout: 60000,
        retries: 3
    }
});

// Update BotUser schema to include permissions
const BotUserSchema = new mongoose.Schema({
    botName: String,
    ownerId: String,
    allowedUsers: [{
        userId: String,
        permissions: {
            canEdit: { type: Boolean, default: false },
            canDelete: { type: Boolean, default: false },
            canStart: { type: Boolean, default: false }
        }
    }],
    autoReconnect: { type: Boolean, default: false }
});

const BotUser = mongoose.model('BotUser', BotUserSchema);


// User Server Count Schema
const UserServerCount = mongoose.model('UserServerCount', new mongoose.Schema({
    userId: String,
    count: { type: Number, default: 0 }
}), 'userservercounts');

// Start HTTP server with improved port conflict handling
console.log('Starting HTTP server...');
const startHttpServer = () => {
    // تعريف دالة للمحاولة على منفذ محدد
    const tryListenOnPort = (port) => {
        console.log(`Attempting to listen on port ${port}...`);

        const server = http.listen(port, '0.0.0.0', () => {
            console.log(`✅ Server is running on port ${port}`);
            console.log(`✅ Server is accessible at: https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`);
            // Start background initialization after server is up
            initializeServices().catch(console.error);
        });

        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.log(`Port ${port} is already in use. Trying next port...`);
                // جرب المنفذ التالي أو منفذ عشوائي

// دالة لحساب حجم المجلد بشكل متكرر
async function calculateDirectorySize(directoryPath) {
    if (!await fs.pathExists(directoryPath)) {
        return 0;
    }
    
    let totalSize = 0;
    
    try {
        const items = await fs.readdir(directoryPath);
        
        for (const item of items) {
            const itemPath = path.join(directoryPath, item);
            const stats = await fs.stat(itemPath).catch(() => ({ size: 0, isDirectory: () => false }));
            
            if (stats.isDirectory()) {
                const subDirSize = await calculateDirectorySize(itemPath);
                totalSize += subDirSize;
            } else {
                totalSize += stats.size;
            }
        }
    } catch (error) {
        console.error(`Error calculating directory size for ${directoryPath}:`, error);
    }
    
    return totalSize;
}

// للتأكد من أن الدالة متاحة بشكل عالمي
global.calculateDirectorySize = calculateDirectorySize;

                const nextPort = port === PORT ? 8080 : 3000;
                tryListenOnPort(nextPort);
            } else {
                console.error('Server error:', err);
                console.error('Attempting to use port 8080 as fallback...');
                if (port !== 8080) {
                    tryListenOnPort(8080);
                } else {
                    process.exit(1);
                }
            }
        });

        return server;
    };

    // Make sure we're binding to all interfaces (0.0.0.0)
    console.log(`Binding server to all interfaces (0.0.0.0) on port ${PORT}`);
    // ابدأ المحاولة على المنفذ الأصلي
    tryListenOnPort(PORT);
};

startHttpServer();

// Passport Configuration
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: process.env.clientId,
    clientSecret: process.env.client_secret,
    callbackURL: process.env.callbackURL,
    scope: ['identify', 'guilds'],
    proxy: true
}, (accessToken, refreshToken, profile, done) => {
    process.nextTick(() => done(null, profile));
}));

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.mongodb,
        ttl: 24 * 60 * 60
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Initialize required directories
app.use(async (req, res, next) => {
    try {
        await fs.ensureDir(path.join(__dirname, 'views'));
        await fs.ensureDir(path.join(__dirname, 'uploads'));
        await fs.ensureDir(path.join(__dirname, 'temp')); // مجلد للملفات المؤقتة مثل النسخ الاحتياطية
        next();
    } catch (error) {
        console.error('Error creating directories:', error);
        next(error);
    }
});

// Asynchronous initialization of services
async function initializeServices() {
    try {
        console.log('Starting background initialization...');

        // Connect to MongoDB
        if (!process.env.mongodb) {
            console.error('❌ MongoDB connection string missing in .env file');
        } else {
            console.log('Connecting to MongoDB...');
            await mongoose.connect(process.env.mongodb, {
                serverSelectionTimeoutMS: 30000,
                socketTimeoutMS: 45000,
                retryWrites: true,
                w: 'majority'
            });
            console.log('✅ Connected to MongoDB successfully');
        }

        // Discord Login
        let discordLoginAttempts = 0;
        const maxLoginAttempts = 3;

        async function attemptDiscordLogin() {
            if (!process.env.token) {
                console.error('❌ Cannot attempt Discord login: token is missing in .env file');
                return;
            }

            try {
                console.log('Attempting Discord bot login...');
                await client.login(process.env.token);
                console.log('✅ Discord bot logged in successfully');
            } catch (err) {
                console.error('❌ Discord bot login error:', err);
                if (discordLoginAttempts < maxLoginAttempts) {
                    discordLoginAttempts++;
                    console.log(`Retrying Discord login (attempt ${discordLoginAttempts}/${maxLoginAttempts})...`);
                    setTimeout(attemptDiscordLogin, 5000);
                } else {
                    console.error('Failed to login to Discord after multiple attempts');
                }
            }
        }

        await attemptDiscordLogin();
        client.once('ready', () => {
            console.log(`✅ Discord bot logged in as ${client.user.tag}`);
        });

        console.log('Background initialization completed');
    } catch (error) {
        console.error('Initialization error:', error);
    }
}

// دالة للبحث عن الملف الرئيسي
async function findMainFile(serverPath) {
    const mainFileNames = ['index.js', 'bot.js', 'main.js', 'server.js'];
    for (const fileName of mainFileNames) {
        const filePath = path.join(serverPath, fileName);
        if (await fs.pathExists(filePath)) {
            return filePath;
        }
    }
    return null;
}

app.get('/', (req, res) => {
    res.render('home', {
        error: req.query.error,
        message: req.query.message,
        isAuthenticated: req.isAuthenticated(),
        user: req.user
    });
});

app.get('/auth/discord', passport.authenticate('discord', {
    prompt: 'consent'
}));

app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/?error=auth_failed' }),
    (req, res) => res.redirect('/dashboard')
);

// مسار اختبار للتحقق من إعدادات OAuth2
app.get('/auth/debug', (req, res) => {
    res.json({
        clientID: process.env.clientId,
        callbackURL: process.env.callbackURL,
        authURL: `https://discord.com/api/oauth2/authorize?client_id=${process.env.clientId}&redirect_uri=${encodeURIComponent(process.env.callbackURL)}&response_type=code&scope=identify%20guilds`,
        environment: {
            NODE_ENV: process.env.NODE_ENV || 'development',
            PORT: process.env.PORT || 3000
        }
    });
});

// تعديل مسار لوحة التحكم لعرض السيرفرات المشتركة
app.get('/dashboard', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

    try {
        const userId = req.user.id;
        const uploadPath = path.join(__dirname, 'uploads', userId);
        let servers = [];

        if (await fs.pathExists(uploadPath)) {
            const items = await fs.readdir(uploadPath);
            servers = items.filter(item =>
                fs.statSync(path.join(uploadPath, item)).isDirectory()
            );
        }

        // التحقق من حالة الاشتراك للمستخدم
        const subsData = await fs.readJSON('subs.json').catch(() => []);
        const userSub = subsData.find(sub => sub.userId === userId);
        const isSubscribed = userSub && new Date(userSub.expiryDate) > new Date();
        
        // حساب الأيام المتبقية للاشتراك
        let remainingDays = 0;
        let subscriptionDetails = null;
        
        if (isSubscribed) {
            remainingDays = Math.ceil((new Date(userSub.expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
            
            // إضافة تفاصيل الاشتراك
            subscriptionDetails = {
                startDate: new Date(userSub.startDate).toLocaleDateString('ar-SA'),
                expiryDate: new Date(userSub.expiryDate).toLocaleDateString('ar-SA'),
                totalDays: userSub.days || 30,
                remainingDays: remainingDays
            };
        }

        // جمع السيرفرات المملوكة مع حالة التشغيل
        const serverData = servers.map(server => ({
            name: server,
            isRunning: processes.has(`${userId}-${server}`),
            isOwner: true
        }));

        // الحصول على السيرفرات المشتركة من قاعدة البيانات
        const sharedServers = await BotUser.find({
            'allowedUsers.userId': userId
        });

        const sharedServerData = sharedServers.map(bot => ({
            name: bot.botName,
            isRunning: processes.has(`${bot.ownerId}-${bot.botName}`),
            isOwner: false,
            ownerId: bot.ownerId
        }));

        // دمج السيرفرات المملوكة والمشتركة
        const allServers = [...serverData, ...sharedServerData];

        // فحص وصول المستخدم للحد الأقصى (2 للمجاني، 5 للمشترك)
        const maxServers = isSubscribed ? 5 : 2;
        const hasReachedLimit = serverData.length >= maxServers;
        const serverCount = serverData.length;

        const userCount = await UserServerCount.findOne({ userId });
        res.render('index', {
            user: req.user,
            servers: allServers,
            userServerCount: userCount ? userCount.count : 0,
            hasReachedLimit: hasReachedLimit,
            isSubscribed: isSubscribed,
            remainingDays: remainingDays,
            subscriptionDetails: subscriptionDetails,
            serverCount: serverCount,
            maxServers: maxServers
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.redirect('/?error=' + encodeURIComponent(error.message));
    }
});

// Middleware to check server access and permissions
const checkServerAccess = async (req, res, next) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { serverName } = req.params;
        if (!serverName) {
            return res.status(400).json({ success: false, error: 'Server name is required' });
        }

        const userId = req.user.id;

        // Check if user is the owner
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const isOwner = await fs.pathExists(serverPath);

        if (isOwner) {
            req.isOwner = true;
            req.userPermissions = { canEdit: true, canDelete: true, canStart: true };
            return next();
        }

        // Check if user has shared access
        const botUser = await BotUser.findOne({
            botName: serverName,
            'allowedUsers.userId': userId
        });

        if (!botUser) {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const userPermission = botUser.allowedUsers.find(user => user.userId === userId);
        if (!userPermission) {
            return res.status(403).json({ success: false, error: 'Permissions not found' });
        }

        req.userPermissions = userPermission.permissions || { canEdit: false, canDelete: false, canStart: false };
        req.ownerId = botUser.ownerId;

        next();
    } catch (error) {
        console.error('Server access check error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
};

// API لتحديث حالة الإعادة التلقائية
// واجهة API لإعداد الويبهوك للسيرفر
app.post('/api/server/:serverName/webhook', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const { webhookUrl } = req.body;
        const userId = req.user.id;

        if (!serverName || !webhookUrl) {
            return res.status(400).json({ success: false, message: 'بيانات غير مكتملة' });
        }

        // التحقق من صحة رابط الويبهوك
        if (!webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
            return res.status(400).json({ success: false, message: 'رابط الويبهوك غير صالح' });
        }

        // قراءة بيانات الويبهوك الحالية
        const webhooksData = JSON.parse(fs.readFileSync(webhooksDB, 'utf8'));
        
        // تحديث أو إضافة الويبهوك الجديد
        if (!webhooksData[userId]) {
            webhooksData[userId] = {};
        }
        
        webhooksData[userId][serverName] = webhookUrl;
        
        // حفظ البيانات المحدثة
        fs.writeFileSync(webhooksDB, JSON.stringify(webhooksData, null, 2), 'utf8');
        
        // إرسال إشعار اختباري إذا نجح الإعداد
        await sendWebhookNotification(userId, serverName, 'تحديث الإعدادات', {
            'نوع الإعداد': 'إعداد الويبهوك',
            'حالة الإعداد': 'تم التكوين بنجاح'
        });
        
        res.json({ success: true, message: 'تم إعداد الويبهوك بنجاح' });
    } catch (error) {
        console.error('Webhook configuration error:', error);
        res.status(500).json({ success: false, message: 'حدث خطأ أثناء إعداد الويبهوك' });
    }
});

// واجهة API لاسترجاع الويبهوك
app.get('/api/server/:serverName/webhook', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.user.id;

        // قراءة بيانات الويبهوك الحالية
        const webhooksData = JSON.parse(fs.readFileSync(webhooksDB, 'utf8'));
        
        // استرجاع الويبهوك المخزن
        const webhookUrl = webhooksData[userId]?.[serverName] || '';
        
        res.json({ success: true, webhookUrl });
    } catch (error) {
        console.error('Webhook retrieval error:', error);
        res.status(500).json({ success: false, message: 'حدث خطأ أثناء استرجاع الويبهوك' });
    }
});

// واجهة API لاختبار الويبهوك
app.post('/api/server/:serverName/webhook/test', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.user.id;
        
        // استخدام الويبهوك المرسل في الطلب أو استرجاع الويبهوك المخزن
        let webhookUrl;
        
        // تحقق من وجود رابط الويبهوك في جسم الطلب
        if (req.body && req.body.webhookUrl) {
            webhookUrl = req.body.webhookUrl;
            
            // التحقق من صحة الرابط
            if (!webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
                return res.status(400).json({ success: false, message: 'رابط الويبهوك غير صالح' });
            }
        } else {
            // قراءة بيانات الويبهوك الحالية من الملف
            const webhooksData = JSON.parse(fs.readFileSync(webhooksDB, 'utf8'));
            
            // استرجاع الويبهوك المخزن
            webhookUrl = webhooksData[userId]?.[serverName];
            
            if (!webhookUrl) {
                return res.status(404).json({ success: false, message: 'الويبهوك غير مُعد' });
            }
        }
        
        // إرسال رسالة اختبارية
        const testData = {
            username: "BotHoster Test Notification",
            avatar_url: "https://i.imgur.com/4M34hi2.png",
            embeds: [{
                title: "اختبار الويبهوك",
                description: `هذه رسالة اختبارية للتأكد من عمل الويبهوك لسيرفر: ${serverName}`,
                color: 0x7289da,
                fields: [
                    {
                        name: "وقت الاختبار",
                        value: new Date().toLocaleString('ar-SA'),
                        inline: true
                    },
                    {
                        name: "المرسل",
                        value: req.user.username || "مستخدم غير معروف",
                        inline: true
                    }
                ],
                timestamp: new Date()
            }]
        };
        
        try {
            const response = await axios.post(webhookUrl, testData);
            
            if (response.status >= 200 && response.status < 300) {
                res.json({ success: true, message: 'تم إرسال رسالة الاختبار بنجاح' });
            } else {
                res.status(400).json({ success: false, message: 'فشل إرسال رسالة الاختبار' });
            }
        } catch (webhookError) {
            console.error('Discord webhook request failed:', webhookError.message);
            const errorMessage = webhookError.response ? 
                `خطأ من Discord: ${webhookError.response.status} ${webhookError.response.statusText}` : 
                'فشل الاتصال بخادم Discord';
            
            res.status(400).json({ success: false, message: errorMessage });
        }
    } catch (error) {
        console.error('Webhook test error:', error);
        res.status(500).json({ success: false, message: 'حدث خطأ أثناء اختبار الويبهوك' });
    }
});

// حذف الويبهوك
app.delete('/api/server/:serverName/webhook', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.user.id;
        
        // قراءة بيانات الويبهوك الحالية
        const webhooksData = JSON.parse(fs.readFileSync(webhooksDB, 'utf8'));
        
        // التحقق من وجود الويبهوك
        if (!webhooksData[userId] || !webhooksData[userId][serverName]) {
            return res.status(404).json({ success: false, message: 'الويبهوك غير موجود' });
        }
        
        // حذف الويبهوك
        delete webhooksData[userId][serverName];
        
        // تنظيف البيانات إذا لم يكن لدى المستخدم أي ويبهوك
        if (Object.keys(webhooksData[userId]).length === 0) {
            delete webhooksData[userId];
        }
        
        // حفظ البيانات المحدثة
        fs.writeFileSync(webhooksDB, JSON.stringify(webhooksData, null, 2), 'utf8');
        
        res.json({ success: true, message: 'تم حذف الويبهوك بنجاح' });
    } catch (error) {
        console.error('Webhook deletion error:', error);
        res.status(500).json({ success: false, message: 'حدث خطأ أثناء حذف الويبهوك' });
    }
});

app.post('/api/bot/auto-reconnect', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { botName, enabled } = req.body;
        const ownerId = req.user.id;

        let botUser = await BotUser.findOne({ botName, ownerId });

        // إذا لم يتم العثور على البوت، قم بإنشائه
        if (!botUser) {
            botUser = new BotUser({
                botName,
                ownerId,
                allowedUsers: [],
                autoReconnect: enabled
            });
        } else {
            botUser.autoReconnect = enabled;
        }

        await botUser.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Auto-reconnect update error:', error);
        res.json({ success: false, error: error.message });
    }
});

// API للحصول على صلاحيات المستخدم
app.get('/api/bot/permissions/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { serverName } = req.params;
        const userId = req.user.id;

        // التحقق مما إذا كان المستخدم هو المالك
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const isOwner = await fs.pathExists(serverPath);

        if (isOwner) {
            return res.json({
                success: true,
                isOwner: true,
                permissions: { canEdit: true, canDelete: true, canStart: true }
            });
        }

        // التحقق من صلاحيات المستخدم المشترك
        const botUser = await BotUser.findOne({
            botName: serverName,
            'allowedUsers.userId': userId
        });

        if (!botUser) {
            return res.json({ success: false, error: 'Access denied' });
        }

        const userPermission = botUser.allowedUsers.find(user => user.userId === userId);

        res.json({
            success: true,
            isOwner: false,
            ownerId: botUser.ownerId,
            permissions: userPermission?.permissions || { canEdit: false, canDelete: false, canStart: false }
        });
    } catch (error) {
        console.error('Error getting permissions:', error);
        res.json({ success: false, error: error.message });
    }
});

// Add new API endpoint to get server permissions
app.get('/api/server/:serverName/permissions', checkServerAccess, async (req, res) => {
    try {
        console.log("Permissions API called for server:", req.params.serverName); // سجل للتشخيص
        const { serverName } = req.params;
        const ownerId = req.isOwner ? req.user.id : req.ownerId;

        console.log("Looking for permissions with owner:", ownerId);

        // الحصول على معلومات المستخدمين المسموح لهم
        let botUser = await BotUser.findOne({
            botName: serverName,
            ownerId: ownerId
        });

        // إذا لم تكن موجودة، قم بإنشاء سجل جديد
        if (!botUser) {
            console.log("No bot user found in database, creating new entry");
            botUser = new BotUser({
                botName: serverName,
                ownerId: ownerId,
                allowedUsers: []
            });
            await botUser.save();
        }

        console.log("Found/created bot user with allowed users:", botUser.allowedUsers?.length || 0);

        // Get Discord user details for each allowed user
        const users = await Promise.all((botUser.allowedUsers || []).map(async (allowedUser) => {
            try {
                // تأكد من أن client متاح ومهيأ
                if (client && client.users && client.users.fetch) {
                    try {
                        const member = await client.users.fetch(allowedUser.userId);
                        return {
                            id: allowedUser.userId,
                            username: member.username || `User_${allowedUser.userId}`,
                            avatar: member.displayAvatarURL() || 'https://cdn.discordapp.com/embed/avatars/0.png',
                            permissions: allowedUser.permissions || { canEdit: false, canDelete: false, canStart: false }
                        };
                    } catch (fetchError) {
                        console.log("Error fetching Discord user, using placeholder:", fetchError.message);
                        return {
                            id: allowedUser.userId,
                            username: `User_${allowedUser.userId}`,
                            avatar: 'https://cdn.discordapp.com/embed/avatars/0.png',
                            permissions: allowedUser.permissions || { canEdit: false, canDelete: false, canStart: false }
                        };
                    }
                } else {
                    console.log("Discord client not ready, using placeholder for:", allowedUser.userId);
                    return {
                        id: allowedUser.userId,
                        username: `User_${allowedUser.userId}`,
                        avatar: 'https://cdn.discordapp.com/embed/avatars/0.png',
                        permissions: allowedUser.permissions || { canEdit: false, canDelete: false, canStart: false }
                    };
                }
            } catch (error) {
                console.error(`Error processing user ${allowedUser.userId}:`, error);
                return {
                    id: allowedUser.userId,
                    username: 'Unknown User',
                    avatar: 'https://cdn.discordapp.com/embed/avatars/0.png',
                    permissions: allowedUser.permissions || { canEdit: false, canDelete: false, canStart: false }
                };
            }
        }));

        console.log("Returning users data:", users.length);
        res.json({ success: true, users, isOwner: req.isOwner });
    } catch (error) {
        console.error('Error getting permissions:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// إضافة API لتصحيح عرض المستخدمين المصرح لهم بطريقة بديلة
app.get('/api/server/:serverName/users', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const ownerId = req.isOwner ? req.user.id : req.ownerId;

        console.log("API جديد لعرض المستخدمين المصرح لهم للسيرفر:", serverName);

        // الحصول على معلومات المستخدمين المسموح لهم
        let botUser = await BotUser.findOne({
            botName: serverName,
            ownerId: ownerId
        });

        if (!botUser) {
            return res.json({ 
                success: true, 
                users: [], 
                isOwner: req.isOwner 
            });
        }

        // تجهيز قائمة المستخدمين مع بيانات بسيطة
        const users = botUser.allowedUsers.map(user => ({
            id: user.userId,
            username: `مستخدم ${user.userId.substring(0, 8)}...`,
            permissions: user.permissions || { canEdit: false, canDelete: false, canStart: false }
        }));

        console.log(`تم العثور على ${users.length} مستخدم مصرح لهم`);
        res.json({ 
            success: true, 
            users, 
            isOwner: req.isOwner 
        });
    } catch (error) {
        console.error('خطأ في استرجاع المستخدمين المصرح لهم:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add new API endpoint to update permissions
app.patch('/api/server/:serverName/permissions/:userId', checkServerAccess, async (req, res) => {
    if (!req.isOwner) {
        return res.status(403).json({ success: false, error: 'Only the owner can modify permissions' });
    }

    try {
        const { serverName, userId } = req.params;
        const { permission, value } = req.body;
        const ownerId = req.user.id;

        const botUser = await BotUser.findOne({ botName: serverName, ownerId });
        if (!botUser) {
            return res.json({ success: false, error: 'Bot not found' });
        }

        const userIndex = botUser.allowedUsers.findIndex(user => user.userId === userId);
        if (userIndex === -1) {
            return res.json({ success: false, error: 'User not found' });
        }

        botUser.allowedUsers[userIndex].permissions[permission] = value;
        await botUser.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Permission update error:', error);
        res.json({ success: false, error: error.message });
    }
});

// Update the add user endpoint to include Discord user validation
app.post('/api/server/:serverName/permissions', checkServerAccess, async (req, res) => {
    if (!req.isOwner) {
        return res.status(403).json({ success: false, error: 'Only the owner can add users' });
    }

    try {
        const { serverName } = req.params;
        const { userId } = req.body;
        const ownerId = req.user.id;

        // Validate Discord user ID
        try {
            await client.users.fetch(userId);
        } catch (error) {
            return res.json({ success: false, error: 'معرف المستخدم غير صالح' });
        }

        let botUser = await BotUser.findOne({ botName: serverName, ownerId });
        if (!botUser) {
            botUser = new BotUser({
                botName: serverName,
                ownerId,
                allowedUsers: []
            });
        }

        if (botUser.allowedUsers.some(user => user.userId === userId)) {
            return res.json({ success: false, error: 'المستخدم مضاف بالفعل' });
        }

        botUser.allowedUsers.push({
            userId,
            permissions: {
                canEdit: false,
                canDelete: false,
                canStart: false
            }
        });
        await botUser.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Add user error:', error);
        res.json({ success: false, error: error.message });
    }
});





// Server routes
app.get('/server/:serverName', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

        if (!await fs.pathExists(serverPath)) {
            return res.redirect('/dashboard?error=Server not found');
        }

        const processKey = userId + "-" + serverName;
        const isRunning = processes.has(processKey);

        // إيجاد الملف الرئيسي
        const mainFile = await findMainFile(serverPath);
        const mainFileName = mainFile ? path.basename(mainFile) : null;

        const botUser = await BotUser.findOne({
            botName: serverName,
            $or: [{ ownerId: req.user.id }, { 'allowedUsers.userId': req.user.id }]
        });

        res.render('server-control', {
            user: req.user,
            serverName,
            isRunning,
            isOwner: req.isOwner,
            userPermissions: req.userPermissions || { canEdit: true, canDelete: true, canStart: true },
            allowedUsers: botUser ? botUser.allowedUsers : [],
            autoReconnect: botUser ? botUser.autoReconnect : false,
            mainFile: mainFileName
        });
    } catch (error) {
        console.error('Server control error:', error);
        res.redirect('/dashboard?error=' + encodeURIComponent('Error accessing server'));
    }
});

app.get('/create-server', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

    try {
        // Check if user is subscribed
        const subsData = await fs.readJSON('subs.json').catch(() => []);
        const userSub = subsData.find(sub => sub.userId === req.user.id);
        const isSubscribed = userSub && new Date(userSub.expiryDate) > new Date();
        
        // Set max servers based on subscription
        const maxServers = isSubscribed ? 5 : 2;
        
        // Check if user has reached the server limit
        const userId = req.user.id;
        const uploadPath = path.join(__dirname, 'uploads', userId);
        let serverCount = 0;

        if (await fs.pathExists(uploadPath)) {
            const items = await fs.readdir(uploadPath);
            serverCount = items.filter(item =>
                fs.statSync(path.join(uploadPath, item)).isDirectory()
            ).length;
        }

        if (serverCount >= maxServers) {
            return res.render('create-server', {
                user: req.user,
                error: `لقد وصلت للحد الأقصى من البوتات (${serverCount}/${maxServers}).${!isSubscribed ? ' قم بترقية حسابك للحصول على المزيد.' : ''}`,
                isSubscribed: isSubscribed
            });
        }

        res.render('create-server', {
            user: req.user,
            error: null,
            isSubscribed: isSubscribed
        });
    } catch (error) {
        console.error('Error checking server count:', error);
        res.render('create-server', {
            user: req.user,
            error: null,
            isSubscribed: false
        });
    }
});

// مسار لتحميل نسخة احتياطية من السيرفر بتنسيق ZIP
app.get('/api/download-backup/:serverName', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        
        // مسار مجلد السيرفر
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        
        if (!await fs.pathExists(serverPath)) {
            return res.status(404).json({ success: false, error: 'السيرفر غير موجود' });
        }
        
        // إنشاء اسم فريد للملف المؤقت
        const timestamp = Date.now();
        const backupFileName = `${serverName}-backup-${timestamp}.zip`;
        const tempFilePath = path.join(__dirname, 'temp', backupFileName);
        
        // إنشاء دفق كتابة الملف
        const output = fs.createWriteStream(tempFilePath);
        const archive = require('archiver')('zip', {
            zlib: { level: 9 } // مستوى ضغط أقصى
        });
        
        // معالجة أحداث دفق الملف
        output.on('close', () => {
            console.log(`✅ تم إنشاء النسخة الاحتياطية: ${backupFileName} - الحجم: ${archive.pointer()} بايت`);
            
            // تعيين رؤوس الاستجابة وإرسال الملف
            res.download(tempFilePath, backupFileName, (err) => {
                if (err) {
                    console.error(`❌ خطأ في تحميل النسخة الاحتياطية:`, err);
                }
                
                // حذف الملف المؤقت بعد التحميل بـ 5 دقائق
                setTimeout(() => {
                    fs.remove(tempFilePath).catch(err => {
                        console.error(`❌ خطأ في حذف الملف المؤقت:`, err);
                    });
                }, 5 * 60 * 1000);
            });
        });
        
        archive.on('error', (err) => {
            console.error(`❌ خطأ في إنشاء الأرشيف:`, err);
            res.status(500).json({ success: false, error: 'خطأ في إنشاء النسخة الاحتياطية' });
        });
        
        // إرفاق دفق الأرشيف بدفق الكتابة
        archive.pipe(output);
        
        // إضافة محتوى مجلد السيرفر إلى الأرشيف
        archive.directory(serverPath, false);
        
        // تنهي عملية إنشاء الأرشيف
        archive.finalize();
        
    } catch (error) {
        console.error(`❌ خطأ في إنشاء النسخة الاحتياطية:`, error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/edit-server/:serverName', checkServerAccess, async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

    try {
        const { serverName } = req.params;
        const ownerId = req.query.ownerId || req.user.id;
        const userId = req.user.id;
        const serverPath = path.join(__dirname, 'uploads', ownerId, serverName);

        if (!await fs.pathExists(serverPath)) {
            return res.redirect('/dashboard?error=Server not found');
        }

        const files = await fs.readdir(serverPath);
        const mainFile = await findMainFile(serverPath);
        const processKey = `${ownerId}-${serverName}`;
        const isRunning = processes.has(processKey);

        res.render('edit-server', {
            user: req.user,
            serverName: serverName,
            files: files,
            mainFile: mainFile ? path.basename(mainFile) : null,
            isRunning: isRunning,
            isOwner: req.isOwner,
            userPermissions: req.userPermissions
        });
    } catch (error) {
        res.redirect('/dashboard?error=' + encodeURIComponent(error.message));
    }
});


app.use(async (req, res, next) => {
    try {
        await fs.ensureDir(path.join(__dirname, 'views'));
        await fs.ensureDir(path.join(__dirname, 'uploads'));
        next();
    } catch (error) {
        console.error('Error creating directories:', error);
        next(error);
    }
});

// Discord Bot Events
client.on('messageCreate', async message => {
    if (message.author.bot) return;

    // التأكد من وجود دالة calculateDirectorySize
    if (typeof calculateDirectorySize !== 'function') {
        global.calculateDirectorySize = async function(directoryPath) {
            if (!await fs.pathExists(directoryPath)) {
                return 0;
            }
            
            let totalSize = 0;
            
            try {
                const items = await fs.readdir(directoryPath);
                
                for (const item of items) {
                    const itemPath = path.join(directoryPath, item);
                    const stats = await fs.stat(itemPath).catch(() => ({ size: 0, isDirectory: () => false }));
                    
                    if (stats.isDirectory()) {
                        const subDirSize = await calculateDirectorySize(itemPath);
                        totalSize += subDirSize;
                    } else {
                        totalSize += stats.size;
                    }
                }
            } catch (error) {
                console.error(`Error calculating directory size for ${directoryPath}:`, error);
            }
            
            return totalSize;
        };
    }

    // Add control panel command
    if (message.content === '!control') {
        try {
            const userId = message.author.id;
            
            // Read subscription data
            const subsData = await fs.readJSON('subs.json').catch(() => []);
            const userSub = subsData.find(sub => sub.userId === userId);
            const isSubscribed = userSub && new Date(userSub.expiryDate) > new Date();
            const remainingDays = isSubscribed ? 
                Math.ceil((new Date(userSub.expiryDate) - new Date()) / (1000 * 60 * 60 * 24)) : 0;

            // Get user's servers
            const uploadPath = path.join(__dirname, 'uploads', userId);
            let servers = [];
            if (await fs.pathExists(uploadPath)) {
                const items = await fs.readdir(uploadPath);
                servers = items.filter(item => {
                    try {
                        return fs.statSync(path.join(uploadPath, item)).isDirectory();
                    } catch (err) {
                        console.error(`Error checking directory ${item}:`, err);
                        return false;
                    }
                });
            }

            // Calculate total size of all servers
            let totalSize = 0;
            for (const server of servers) {
                try {
                    const serverPath = path.join(uploadPath, server);
                    // استخدام دالة لحساب حجم المجلد بشكل متكرر
                    totalSize += await calculateDirectorySize(serverPath);
                } catch (err) {
                    console.error(`Error calculating size for ${server}:`, err);
                }
            }
            const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(2);
            
            // Create initial embed
            const embed = new Discord.EmbedBuilder()
                .setColor(isSubscribed ? '#4fd69c' : '#f16a6a')
                .setTitle('🎮 لوحة التحكم')
                .setDescription('مرحباً بك في لوحة التحكم الخاصة بك')
                .addFields(
                    { 
                        name: '💎 حالة الاشتراك',
                        value: isSubscribed ? 
                            `✅ مشترك - متبقي ${remainingDays} يوم` : 
                            '❌ غير مشترك'
                    },
                    {
                        name: '🤖 السيرفرات',
                        value: `عدد السيرفرات: ${servers.length}/${isSubscribed ? '5' : '2'}\nالحجم الإجمالي: ${totalSizeMB} MB`
                    }
                )
                .setFooter({ 
                    text: message.author.username, 
                    iconURL: message.author.displayAvatarURL() 
                })
                .setTimestamp();

            // Create server selection menu with options
            const serverMenuOptions = servers.map(server => {
                try {
                    const serverPath = path.join(uploadPath, server);
                    const serverSize = fs.existsSync(serverPath) ? 
                        (fs.statSync(serverPath).size / (1024 * 1024)).toFixed(2) : '0.00';
                    
                    return {
                        label: server,
                        description: `حجم السيرفر: ${serverSize} MB`,
                        value: server
                    };
                } catch (err) {
                    console.error(`Error processing server ${server}:`, err);
                    return {
                        label: server,
                        description: 'خطأ في قراءة المعلومات',
                        value: server
                    };
                }
            });
            
            // تحقق من عدم وجود سيرفرات
            if (serverMenuOptions.length === 0) {
                serverMenuOptions.push({
                    label: 'لا توجد سيرفرات',
                    description: 'قم بإنشاء سيرفر جديد',
                    value: 'no_servers',
                    default: true
                });
            }
            
            const serverMenu = new Discord.StringSelectMenuBuilder()
                .setCustomId('server_select')
                .setPlaceholder('اختر سيرفر للتحكم')
                .addOptions(serverMenuOptions);

            // Create main action row with subscription and create buttons
            const mainRow = new Discord.ActionRowBuilder()
                .addComponents(
                    new Discord.ButtonBuilder()
                        .setCustomId('subscription')
                        .setLabel('الاشتراك')
                        .setStyle(isSubscribed ? Discord.ButtonStyle.Success : Discord.ButtonStyle.Danger)
                        .setEmoji('💎'),
                    new Discord.ButtonBuilder()
                        .setCustomId('create_server')
                        .setLabel('إنشاء سيرفر')
                        .setStyle(Discord.ButtonStyle.Primary)
                        .setEmoji('➕')
                        .setDisabled(servers.length >= (isSubscribed ? 5 : 2))
                );

            // Create server selection row
            const serverRow = new Discord.ActionRowBuilder()
                .addComponents(serverMenu);

            // Send initial message
            const controlMsg = await message.channel.send({
                embeds: [embed],
                components: [mainRow, serverRow]
            });

            // Store message reference globally for avoiding collector conflicts
            global.activeControlPanels = global.activeControlPanels || new Map();
            global.activeControlPanels.set(controlMsg.id, {
                userId: message.author.id,
                channelId: message.channel.id
            });

            // Create collector for interactions with a unique filter
            const collector = controlMsg.createMessageComponentCollector({ 
                filter: i => {
                    const panelInfo = global.activeControlPanels.get(i.message.id);
                    return panelInfo && panelInfo.userId === i.user.id;
                },
                time: 600000 // 10 minutes
            });

            collector.on('collect', async interaction => {
                if (!interaction.isButton() && !interaction.isStringSelectMenu()) return;
                
                // Double-check authorization
                if (interaction.user.id !== message.author.id) {
                    return interaction.reply({ 
                        content: 'عذراً، هذه اللوحة خاصة بصاحب الأمر فقط',
                        ephemeral: true 
                    });
                }

                try {
                    if (interaction.customId === 'subscription') {
                        // Show subscription details
                        const subEmbed = new Discord.EmbedBuilder()
                            .setColor(isSubscribed ? '#4fd69c' : '#f16a6a')
                            .setTitle('💎 تفاصيل الاشتراك')
                            .addFields(
                                { 
                                    name: 'الحالة', 
                                    value: isSubscribed ? '✅ مشترك' : '❌ غير مشترك' 
                                },
                                { 
                                    name: 'الأيام المتبقية', 
                                    value: isSubscribed ? `${remainingDays} يوم` : '0' 
                                },
                                {
                                    name: 'المميزات',
                                    value: '• 5 سيرفرات كحد أقصى\n• دعم فني متواصل\n• تحديثات حصرية'
                                }
                            );

                        await interaction.reply({ 
                            embeds: [subEmbed], 
                            ephemeral: true 
                        });
                    }
                    else if (interaction.customId === 'create_server') {
                        // Show server creation modal
                        const modal = new Discord.ModalBuilder()
                            .setCustomId('create_server_modal')
                            .setTitle('إنشاء سيرفر جديد');

                        const serverNameInput = new Discord.TextInputBuilder()
                            .setCustomId('server_name')
                            .setLabel('اسم السيرفر')
                            .setStyle(Discord.TextInputStyle.Short)
                            .setPlaceholder('أدخل اسم السيرفر هنا')
                            .setRequired(true);

                        const firstRow = new Discord.ActionRowBuilder().addComponents(serverNameInput);
                        modal.addComponents(firstRow);

                        await interaction.showModal(modal);
                    }
                    else if (interaction.customId === 'server_select') {
                        if (interaction.values[0] === 'no_servers') {
                            return interaction.reply({
                                content: '❌ لا توجد سيرفرات متاحة. قم بإنشاء سيرفر جديد أولاً.',
                                ephemeral: true
                            });
                        }
                        
                        const selectedServer = interaction.values[0];
                        const serverPath = path.join(uploadPath, selectedServer);
                        
                        // احسب حجم السيرفر بشكل دقيق
                        let serverSize = 0;
                        try {
                            serverSize = await calculateDirectorySize(serverPath);
                        } catch (sizeError) {
                            console.error(`Error calculating size for ${selectedServer}:`, sizeError);
                        }
                        const size = (serverSize / (1024 * 1024)).toFixed(2);
                        
                        // تحقق من حالة التشغيل
                        const processKey = `${userId}-${selectedServer}`;
                        const isRunning = processes.has(processKey);

                        // إنشاء صف أزرار التحكم الأساسية
                        const serverControls = new Discord.ActionRowBuilder()
                            .addComponents(
                                new Discord.ButtonBuilder()
                                    .setCustomId(`start_${selectedServer}`)
                                    .setLabel('تشغيل')
                                    .setStyle(Discord.ButtonStyle.Success)
                                    .setEmoji('▶️')
                                    .setDisabled(isRunning),
                                new Discord.ButtonBuilder()
                                    .setCustomId(`stop_${selectedServer}`)
                                    .setLabel('إيقاف')
                                    .setStyle(Discord.ButtonStyle.Danger)
                                    .setEmoji('⏹️')
                                    .setDisabled(!isRunning),
                                new Discord.ButtonBuilder()
                                    .setCustomId(`delete_${selectedServer}`)
                                    .setLabel('حذف')
                                    .setStyle(Discord.ButtonStyle.Danger)
                                    .setEmoji('🗑️'),
                                new Discord.ButtonBuilder()
                                    .setCustomId(`add_user_${selectedServer}`)
                                    .setLabel('إضافة مستخدم')
                                    .setStyle(Discord.ButtonStyle.Primary)
                                    .setEmoji('👥')
                            );
                        
                        // إنشاء صف ثاني للأزرار الإضافية
                        const additionalControls = new Discord.ActionRowBuilder()
                            .addComponents(
                                new Discord.ButtonBuilder()
                                    .setCustomId(`files_${selectedServer}`)
                                    .setLabel('ملفاتي')
                                    .setStyle(Discord.ButtonStyle.Primary)
                                    .setEmoji('📁'),
                                new Discord.ButtonBuilder()
                                    .setCustomId(`zip_${selectedServer}`)
                                    .setLabel('تحميل كـ ZIP')
                                    .setStyle(Discord.ButtonStyle.Secondary)
                                    .setEmoji('📦'),
                                new Discord.ButtonBuilder()
                                    .setCustomId('back')
                                    .setLabel('عودة')
                                    .setStyle(Discord.ButtonStyle.Secondary)
                                    .setEmoji('↩️')
                            );

                        // Update embed with server details
                        const serverEmbed = new Discord.EmbedBuilder()
                            .setColor('#3a57a4')
                            .setTitle(`🤖 سيرفر: ${selectedServer}`)
                            .addFields(
                                { name: 'الحالة', value: isRunning ? '🟢 يعمل' : '🔴 متوقف' },
                                { name: 'الحجم', value: `📊 ${size} MB` }
                            )
                            .setFooter({ 
                                text: message.author.username, 
                                iconURL: message.author.displayAvatarURL() 
                            })
                            .setTimestamp();

                        await interaction.update({
                            embeds: [serverEmbed],
                            components: [serverControls, additionalControls, serverRow]
                        });
                    }
                    else if (interaction.customId.startsWith('start_')) {
                        const serverName = interaction.customId.replace('start_', '');
                        const serverPath = path.join(uploadPath, serverName);
                        
                        // Progress tracking message
                        const progressEmbed = new Discord.EmbedBuilder()
                            .setColor('#4fd69c')
                            .setTitle('🚀 جاري تشغيل السيرفر')
                            .setDescription('```js\n[+] جاري التحقق من الملفات...\n```')
                            .setFooter({ text: '0%' });
                        
                        await interaction.reply({
                            embeds: [progressEmbed],
                            ephemeral: true
                        });

                        try {
                            // Update progress with pauses
                            for (let i = 0; i <= 100; i += 20) {
                                await new Promise(resolve => setTimeout(resolve, 1000));
                                const status = i === 0 ? 'جاري التحقق من الملفات...' :
                                            i === 20 ? 'جاري تحميل المكتبات...' :
                                            i === 40 ? 'جاري تهيئة البوت...' :
                                            i === 60 ? 'جاري الاتصال بـ Discord...' :
                                            i === 80 ? 'جاري تشغيل السيرفر...' :
                                            'اكتمل التشغيل!';
                                
                                progressEmbed.setDescription(`\`\`\`js\n[+] ${status}\n\`\`\``)
                                           .setFooter({ text: `${i}%` });
                                
                                try {
                                    await interaction.editReply({ embeds: [progressEmbed] });
                                } catch (editError) {
                                    console.error("Error updating progress:", editError);
                                }
                            }

                            // Actually start the server with proper error handling
                            const mainFile = await findMainFile(serverPath);
                            if (!mainFile) {
                                throw new Error('لم يتم العثور على الملف الرئيسي');
                            }
                            
                            // تشغيل السيرفر مع متغيرات البيئة المناسبة
                            const processInstance = spawn('node', [mainFile], {
                                cwd: serverPath,
                                env: { 
                                    ...process.env, 
                                    DISCORD_TOKEN: process.env.token 
                                }
                            });
                            
                            // تخزين العملية مع بيانات إضافية
                            processes.set(`${userId}-${serverName}`, {
                                process: processInstance,
                                output: [],
                                startTime: Date.now()
                            });
                            
                            // إعداد معالجة الخرج والأخطاء
                            processInstance.stdout.on('data', (data) => {

// مسار لتنزيل ملفات الـ ZIP
app.get('/download-zip/:userId/:serverName', async (req, res) => {
    try {
        const { userId, serverName } = req.params;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        
        // تحقق من وجود السيرفر
        if (!await fs.pathExists(serverPath)) {
            return res.status(404).send('السيرفر غير موجود');
        }
        
        // إنشاء ملف ZIP مؤقت
        const archiver = require('archiver');
        const tempZipPath = path.join(__dirname, 'temp', `${serverName}-${Date.now()}.zip`);
        
        // التأكد من وجود مجلد temp
        await fs.ensureDir(path.join(__dirname, 'temp'));
        
        // إنشاء كاتب الملفات وأرشيف مضغوط
        const output = fs.createWriteStream(tempZipPath);
        const archive = archiver('zip', {
            zlib: { level: 9 } // مستوى الضغط الأقصى
        });
        
        // معالجة الأحداث
        output.on('close', () => {
            console.log(`ZIP created: ${tempZipPath} (${archive.pointer()} bytes)`);
            
            // إرسال الملف للتنزيل
            res.download(tempZipPath, `${serverName}.zip`, err => {
                if (err) {
                    console.error('Error sending zip file:', err);
                }
                
                // حذف الملف المؤقت بعد التنزيل
                setTimeout(() => {
                    fs.unlink(tempZipPath).catch(err => {
                        console.error('Error deleting temp zip file:', err);
                    });
                }, 60000); // حذف الملف بعد دقيقة
            });
        });
        
        archive.on('error', err => {
            console.error('Error creating archive:', err);
            res.status(500).send('حدث خطأ أثناء إنشاء الأرشيف');
        });
        
        // توجيه الأرشيف إلى الكاتب
        archive.pipe(output);
        
        // إضافة محتويات مجلد السيرفر إلى الأرشيف
        archive.directory(serverPath, false);
        
        // إنهاء عملية الأرشفة
        archive.finalize();
    } catch (error) {
        console.error('Error generating zip file:', error);
        res.status(500).send('حدث خطأ أثناء إنشاء ملف الـ ZIP');
    }
});

                                const output = data.toString();
                                console.log(`[${serverName}] stdout:`, output);
                                const processData = processes.get(`${userId}-${serverName}`);
                                if (processData) {
                                    processData.output.push(output);
                                }
                            });
                            
                            processInstance.stderr.on('data', (data) => {
                                const output = data.toString();
                                console.error(`[${serverName}] stderr:`, output);
                                const processData = processes.get(`${userId}-${serverName}`);
                                if (processData) {
                                    processData.output.push(output);
                                }
                            });
                            
                            processInstance.on('close', async (code) => {
                                console.log(`[${serverName}] Process closed with code ${code}`);
                                processes.delete(`${userId}-${serverName}`);
                                
                                // التحقق من إعادة الاتصال التلقائية
                                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                                if (botUser && botUser.autoReconnect) {
                                    console.log(`Auto reconnecting bot: ${serverName}`);
                                    setTimeout(() => {
                                        const startProcess = spawn('node', [mainFile], {
                                            cwd: serverPath,
                                            env: { ...process.env, DISCORD_TOKEN: process.env.token }
                                        });
                                        
                                        processes.set(`${userId}-${serverName}`, {
                                            process: startProcess,
                                            output: [],
                                            startTime: Date.now()
                                        });
                                    }, 5000);
                                }
                            });

                            // Final success message
                            progressEmbed.setColor('#4fd69c')
                                       .setTitle('✅ تم تشغيل السيرفر')
                                       .setDescription('```js\n[+] تم تشغيل السيرفر بنجاح!\n```')
                                       .setFooter({ text: '100%' });
                            
                            await interaction.editReply({ embeds: [progressEmbed] });

                            // تحديث حالة الأزرار في لوحة التحكم
                            if (interaction.message && interaction.message.components && interaction.message.components[0]) {
                                const startButton = interaction.message.components[0].components.find(c => c.data.custom_id === `start_${serverName}`);
                                const stopButton = interaction.message.components[0].components.find(c => c.data.custom_id === `stop_${serverName}`);
                                
                                if (startButton) startButton.setDisabled(true);
                                if (stopButton) stopButton.setDisabled(false);
                                
                                await interaction.message.edit({ components: interaction.message.components });
                            }
                        } catch (error) {
                            console.error('Error starting server:', error);
                            progressEmbed.setColor('#f16a6a')
                                       .setTitle('❌ فشل تشغيل السيرفر')
                                       .setDescription(`\`\`\`js\n[-] ${error.message}\n\`\`\``)
                                       .setFooter({ text: 'فشل' });
                            
                            await progressMsg.edit({ embeds: [progressEmbed] });
                        }
                    }
                    else if (interaction.customId.startsWith('stop_')) {
                        const serverName = interaction.customId.replace('stop_', '');
                        const processKey = `${userId}-${serverName}`;
                        const processData = processes.get(processKey);
                        
                        if (processData && processData.process) {
                            try {
                                // إيقاف العملية بأمان
                                processData.process.kill('SIGTERM');
                                processes.delete(processKey);
                                
                                // تحديث حالة الأزرار - إصلاح خطأ startButton.setDisabled
                                if (interaction.message && interaction.message.components && interaction.message.components[0]) {
                                    // إنشاء نسخة جديدة من الأزرار بدلاً من محاولة تحديث القديمة
                                    const currentComponents = interaction.message.components;
                                    
                                    // نسخ الصف الأول من الأزرار وتحديثها
                                    const updatedServerControls = new Discord.ActionRowBuilder();
                                    
                                    // استخراج الأزرار الحالية للصف الأول
                                    const currentButtons = currentComponents[0].components;
                                    
                                    // إعادة إنشاء الأزرار مع تحديث حالة التعطيل
                                    for (const button of currentButtons) {
                                        const newButton = Discord.ButtonBuilder.from(button);
                                        
                                        // تحديث حالة أزرار التشغيل والإيقاف
                                        if (button.data.custom_id === `start_${serverName}`) {
                                            newButton.setDisabled(false);
                                        } else if (button.data.custom_id === `stop_${serverName}`) {
                                            newButton.setDisabled(true);
                                        }
                                        
                                        updatedServerControls.addComponents(newButton);
                                    }
                                    
                                    // تحديث الرسالة بالأزرار الجديدة
                                    const newComponents = [updatedServerControls];
                                    if (currentComponents.length > 1) {
                                        // إضافة باقي الصفوف كما هي
                                        for (let i = 1; i < currentComponents.length; i++) {
                                            newComponents.push(currentComponents[i]);
                                        }
                                    }
                                    
                                    await interaction.message.edit({ components: newComponents });
                                }
                                
                                await interaction.reply({
                                    content: `✅ تم إيقاف سيرفر ${serverName} بنجاح`,
                                    ephemeral: true
                                });
                            } catch (stopError) {
                                console.error(`Error stopping server ${serverName}:`, stopError);
                                await interaction.reply({
                                    content: `❌ حدث خطأ أثناء إيقاف السيرفر: ${stopError.message}`,
                                    ephemeral: true
                                });
                            }
                        } else {
                            await interaction.reply({
                                content: `⚠️ السيرفر ${serverName} غير مشغل حالياً`,
                                ephemeral: true
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('delete_')) {
                        const serverName = interaction.customId.replace('delete_', '');
                        
                        // Show confirmation buttons
                        const confirmRow = new Discord.ActionRowBuilder()
                            .addComponents(
                                new Discord.ButtonBuilder()
                                    .setCustomId(`confirm_delete_${serverName}`)
                                    .setLabel('تأكيد الحذف')
                                    .setStyle(Discord.ButtonStyle.Danger)
                                    .setEmoji('⚠️'),
                                new Discord.ButtonBuilder()
                                    .setCustomId(`cancel_delete_${serverName}`)
                                    .setLabel('إلغاء')
                                    .setStyle(Discord.ButtonStyle.Secondary)
                                    .setEmoji('✖️')
                            );

                        await interaction.reply({
                            content: `⚠️ هل أنت متأكد من حذف سيرفر ${serverName}؟ هذا الإجراء لا يمكن التراجع عنه!`,
                            components: [confirmRow],
                            ephemeral: true
                        });
                    }
                    else if (interaction.customId.startsWith('confirm_delete_')) {
                        const serverName = interaction.customId.replace('confirm_delete_', '');
                        const serverPath = path.join(uploadPath, serverName);
                        
                        try {
                            // استخدام deferUpdate بدلاً من update للتعامل مع التفاعل بشكل أفضل
                            await interaction.deferUpdate();
                            
                            // ثم تحديث الرسالة
                            await interaction.editReply({
                                content: `⏳ جاري حذف سيرفر ${serverName}...`,
                                components: [],
                                ephemeral: true
                            }).catch(console.error);
                            
                            // Stop server if running
                            const processKey = `${userId}-${serverName}`;
                            const processData = processes.get(processKey);
                            if (processData && processData.process) {
                                processData.process.kill('SIGTERM');
                                processes.delete(processKey);
                            }
                            
                            // Delete server files
                            await fs.remove(serverPath);
                            
                            // انتظار قليلاً لضمان اكتمال الحذف
                            await new Promise(resolve => setTimeout(resolve, 500));
                            
                            // استخدام followUp بدلاً من update لتجنب أخطاء التفاعل
                            await interaction.followUp({
                                content: `✅ تم حذف سيرفر ${serverName} بنجاح`,
                                ephemeral: true
                            });
                            
                            // Return to main control panel safely using a new message
                            setTimeout(() => {
                                message.channel.send('!control').catch(err => {
                                    console.error('Error sending new control panel:', err);
                                });
                            }, 1500);
                        } catch (deleteError) {
                            console.error(`Error deleting server ${serverName}:`, deleteError);
                            
                            // استخدام followUp لضمان الاستجابة
                            await interaction.followUp({
                                content: `❌ حدث خطأ أثناء حذف السيرفر: ${deleteError.message}`,
                                ephemeral: true
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('cancel_delete_')) {
                        // إلغاء عملية الحذف
                        await interaction.update({
                            content: '✅ تم إلغاء عملية الحذف',
                            components: [],
                            ephemeral: true
                        });
                    }
                    else if (interaction.customId.startsWith('add_user_')) {
                        const serverName = interaction.customId.replace('add_user_', '');
                        
                        try {
                            // الحصول على قائمة المستخدمين المصرح لهم حالياً
                            let botUser = await BotUser.findOne({ 
                                botName: serverName,
                                ownerId: message.author.id
                            });
                            
                            if (!botUser) {
                                botUser = new BotUser({
                                    botName: serverName,
                                    ownerId: message.author.id,
                                    allowedUsers: []
                                });
                                await botUser.save();
                            }
                            
                            // عرض المودال مباشرةً لتسهيل إضافة مستخدم جديد
                            // أولاً عرض معلومات المستخدمين الحاليين
                            let userList = '';
                            if (botUser.allowedUsers && botUser.allowedUsers.length > 0) {
                                userList = 'المستخدمون المصرح لهم حالياً:\n' + 
                                    botUser.allowedUsers.map((user, index) => 
                                        `${index + 1}. \`${user.userId}\``
                                    ).join('\n') + '\n\n';
                            } else {
                                userList = 'لا يوجد مستخدمين مصرح لهم حالياً\n\n';
                            }
                            
                            await interaction.reply({
                                content: `📝 **إدارة المستخدمين لسيرفر ${serverName}**\n\n${userList}اضغط على الزر أدناه لإضافة مستخدم جديد.`,
                                components: [
                                    new Discord.ActionRowBuilder()
                                        .addComponents(
                                            new Discord.ButtonBuilder()
                                                .setCustomId(`new_user_${serverName}`)
                                                .setLabel('إضافة مستخدم جديد')
                                                .setStyle(Discord.ButtonStyle.Primary)
                                                .setEmoji('👤')
                                        )
                                ],
                                ephemeral: true
                            });
                            
                            // إنشاء قائمة منسدلة منفصلة إذا كان هناك مستخدمين
                            if (botUser.allowedUsers && botUser.allowedUsers.length > 0) {
                                const userOptions = botUser.allowedUsers.map(user => ({
                                    label: `مستخدم: ${user.userId}`,
                                    description: 'اضغط للإزالة',
                                    value: user.userId
                                }));
                                
                                const userSelect = new Discord.StringSelectMenuBuilder()
                                    .setCustomId(`remove_user_${serverName}`)
                                    .setPlaceholder('اختر مستخدم لإزالته')
                                    .addOptions(userOptions);
                                    
                                await interaction.followUp({
                                    content: '✨ **إزالة المستخدمين**\nيمكنك اختيار مستخدم من القائمة أدناه لإزالته:',
                                    components: [new Discord.ActionRowBuilder().addComponents(userSelect)],
                                    ephemeral: true
                                });
                            }
                            
                        } catch (error) {
                            console.error('Error loading users:', error);
                            await interaction.reply({
                                content: `❌ حدث خطأ أثناء تحميل المستخدمين: ${error.message}`,
                                ephemeral: true
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('remove_user_')) {
                        const serverName = interaction.customId.replace('remove_user_', '');
                        const selectedUserId = interaction.values[0];
                        
                        // حذف المستخدم من السيرفر
                        let botUser = await BotUser.findOne({ 
                            botName: serverName,
                            ownerId: message.author.id
                        });
                        
                        if (botUser) {
                            // تحديث قائمة المستخدمين
                            botUser.allowedUsers = botUser.allowedUsers.filter(user => 
                                user.userId !== selectedUserId
                            );
                            
                            await botUser.save();
                            
                            await interaction.update({
                                content: `✅ تم إزالة المستخدم \`${selectedUserId}\` من سيرفر ${serverName} بنجاح`,
                                components: []
                            });
                        } else {
                            await interaction.update({
                                content: '❌ حدث خطأ أثناء إزالة المستخدم',
                                components: []
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('new_user_')) {
                        const serverName = interaction.customId.replace('new_user_', '');
                        
                        try {
                            console.log("Showing user add modal for server:", serverName);
                            
                            // Show modal for user ID input
                            const modal = new Discord.ModalBuilder()
                                .setCustomId(`add_user_modal_${serverName}`)
                                .setTitle('إضافة مستخدم للسيرفر');
    
                            const userIdInput = new Discord.TextInputBuilder()
                                .setCustomId('user_id')
                                .setLabel('معرف المستخدم')
                                .setStyle(Discord.TextInputStyle.Short)
                                .setPlaceholder('أدخل معرف المستخدم هنا')
                                .setRequired(true);
    
                            const firstRow = new Discord.ActionRowBuilder().addComponents(userIdInput);
                            modal.addComponents(firstRow);
    
                            await interaction.showModal(modal);
                            console.log("Modal shown successfully");
                        } catch (modalError) {
                            console.error("Error showing user modal:", modalError);
                            await interaction.reply({
                                content: `❌ حدث خطأ أثناء فتح نافذة إضافة المستخدم: ${modalError.message}`,
                                ephemeral: true
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('files_')) {
                        const serverName = interaction.customId.replace('files_', '');
                        const serverPath = path.join(uploadPath, serverName);
                        
                        try {
                            // الحصول على قائمة الملفات والمجلدات
                            const items = await fs.readdir(serverPath);
                            
                            // تحضير معلومات الملفات
                            const fileDetails = await Promise.all(items.map(async (item) => {
                                const itemPath = path.join(serverPath, item);
                                const stats = await fs.stat(itemPath);
                                return {
                                    name: item,
                                    isDirectory: stats.isDirectory(),
                                    size: (stats.size / 1024).toFixed(2) + ' KB',
                                    modified: stats.mtime.toLocaleString()
                                };
                            }));
                            
                            // تصنيف الملفات: المجلدات أولاً ثم الملفات
                            fileDetails.sort((a, b) => {
                                if (a.isDirectory && !b.isDirectory) return -1;
                                if (!a.isDirectory && b.isDirectory) return 1;
                                return a.name.localeCompare(b.name);
                            });
                            
                            // إنشاء نص الملفات
                            let filesList = fileDetails.map(file => {
                                const icon = file.isDirectory ? '📁' : '📄';
                                return `${icon} ${file.name} (${file.size})`;
                            }).join('\n');
                            
                            if (filesList.length === 0) {
                                filesList = 'لا توجد ملفات';
                            }
                            
                            // إرسال قائمة الملفات
                            await interaction.reply({
                                content: `**📁 ملفات سيرفر ${serverName}:**\n\n${filesList}`,
                                ephemeral: true
                            });
                        } catch (error) {
                            console.error(`Error listing files for ${serverName}:`, error);
                            await interaction.reply({
                                content: `❌ حدث خطأ أثناء قراءة الملفات: ${error.message}`,
                                ephemeral: true
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('zip_')) {
                        const serverName = interaction.customId.replace('zip_', '');
                        const serverPath = path.join(uploadPath, serverName);
                        
                        // حساب الحجم الإجمالي للسيرفر
                        const serverSize = await calculateDirectorySize(serverPath);
                        const sizeMB = (serverSize / (1024 * 1024)).toFixed(2);
                        
                        // إنشاء رابط التحميل
                        const downloadLink = `/download-zip/${userId}/${encodeURIComponent(serverName)}`;
                        
                        // إنشاء رابط كامل مع معالجة صحيحة
                        let fullDownloadUrl = '';
                        
                        // التحقق من وجود متغيرات البيئة
                        if (process.env.REPL_SLUG && process.env.REPL_OWNER) {
                            fullDownloadUrl = `http://fi9.bot-hosting.net:21163${downloadLink}`;
                        } else {
                            // استخدام رابط مباشر للتطبيق
                            const PORT = process.env.PORT || 21163;
                            fullDownloadUrl = `http://fi9.bot-hosting.net:21163${downloadLink}`;
                        }
                        
                        // إرسال معلومات التحميل
                        const zipEmbed = new Discord.EmbedBuilder()
                            .setColor('#3a57a4')
                            .setTitle(`📦 تحميل ملفات سيرفر ${serverName}`)
                            .setDescription(`يمكنك تحميل جميع ملفات السيرفر كملف ZIP.\n\nحجم الملفات: **${sizeMB} MB**\n\nالرابط المباشر للتحميل:\n${fullDownloadUrl}`)
                            .setFooter({ 
                                text: 'يمكنك تنزيل الملفات من لوحة التحكم على الموقع',
                                iconURL: message.author.displayAvatarURL() 
                            });
                        
                        const downloadButton = new Discord.ActionRowBuilder()
                            .addComponents(
                                new Discord.ButtonBuilder()
                                    .setLabel('تحميل ZIP')
                                    .setStyle(Discord.ButtonStyle.Link)
                                    .setURL(fullDownloadUrl)
                                    .setEmoji('📥')
                            );
                            
                        await interaction.reply({
                            embeds: [zipEmbed],
                            components: [downloadButton],
                            ephemeral: true
                        });
                    }
                    else if (interaction.customId === 'back') {
                        // إعلام المستخدم أولاً بأنه سيتم العودة للوحة التحكم
                        await interaction.reply({
                            content: '⏳ جاري العودة للوحة التحكم الرئيسية...',
                            ephemeral: true
                        });
                        
                        // إرسال رسالة جديدة بلوحة التحكم بعد مهلة قصيرة
                        setTimeout(() => {
                            interaction.channel.send('!control').then(async () => {
                                // إخبار المستخدم بأنه تم إرسال لوحة تحكم جديدة في المحادثة
                                await interaction.followUp({
                                    content: '✅ تم إرسال لوحة التحكم الرئيسية في المحادثة.',
                                    ephemeral: true
                                }).catch(e => console.error("Couldn't send follow-up message:", e));
                            }).catch(err => {
                                console.error('Error sending new control panel:', err);
                                interaction.followUp({
                                    content: '❌ حدث خطأ أثناء العودة للوحة التحكم. الرجاء كتابة `!control` مرة أخرى.',
                                    ephemeral: true
                                }).catch(e => console.error("Couldn't send error message:", e));
                            });
                        }, 500);
                    }
                } catch (error) {
                    console.error('Control panel error:', error);
                    
                    // محاولة الرد على التفاعل إذا لم يتم الرد عليه بعد
                    try {
                        const replyMethod = interaction.replied || interaction.deferred ? 'followUp' : 'reply';
                        await interaction[replyMethod]({ 
                            content: `❌ حدث خطأ أثناء تنفيذ العملية: ${error.message}`,
                            ephemeral: true 
                        });
                    } catch (replyError) {
                        console.error('Error replying to interaction:', replyError);
                    }
                }
            });

            // Modal submit handling - نحتفظ بها خارج المجمع لتجنب التداخل
            client.on('interactionCreate', async interaction => {
                // تسجيل التفاعل للتشخيص
                console.log(`Interaction received: ${interaction.type} - ${interaction.customId || 'No ID'}`);
                
                if (!interaction.isModalSubmit()) return;

                try {
                    if (interaction.customId === 'create_server_modal') {
                        const serverName = interaction.fields.getTextInputValue('server_name');
                        
                        // استخراج معرف المستخدم من التخزين العالمي
                        const userId = interaction.user.id;
                        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

                        // Check if server name is valid - السماح بالأحرف العربية أيضاً
                        if (!/^[\u0600-\u06FFa-zA-Z0-9-_]+$/.test(serverName)) {
                            return interaction.reply({
                                content: '❌ اسم السيرفر يجب أن يحتوي على أحرف عربية أو إنجليزية أو أرقام أو شرطات فقط',
                                ephemeral: true
                            });
                        }

                        // Check if server already exists
                        if (await fs.pathExists(serverPath)) {
                            return interaction.reply({
                                content: '❌ يوجد سيرفر بهذا الاسم بالفعل',
                                ephemeral: true
                            });
                        }

                        // Create progress embed
                        const progressEmbed = new Discord.EmbedBuilder()
                            .setColor('#3a57a4')
                            .setTitle('🚀 جاري إنشاء السيرفر')
                            .setDescription('```js\n[+] جاري إنشاء المجلد...\n```')
                            .setFooter({ text: '0%' });

                        // استخدام دوال الرد المناسبة
                        await interaction.reply({
                            embeds: [progressEmbed],
                            ephemeral: true
                        });

                        // استخدام التاخير الزمني للتحديث
                        let replyPromise = Promise.resolve();
                        
                        // Simulate progress with actual file creation
                        try {
                            // التأكد من وجود مجلد للمستخدم
                            await fs.ensureDir(path.dirname(serverPath));
                            
                            // إنشاء المجلد أولاً
                            await fs.ensureDir(serverPath);
                            
                            for (let i = 0; i <= 100; i += 20) {
                                // استخدام بيان await لانتظار تحديث الرسالة السابقة
                                await replyPromise;
                                
                                // انتظار لتظهر التحديثات بشكل متدرج
                                await new Promise(resolve => setTimeout(resolve, 800));
                                
                                const status = i === 0 ? 'جاري إنشاء المجلد...' :
                                            i === 20 ? 'جاري إنشاء الملفات الأساسية...' :
                                            i === 40 ? 'جاري تثبيت المكتبات...' :
                                            i === 60 ? 'جاري إعداد التكوين...' :
                                            i === 80 ? 'جاري إنهاء الإعداد...' :
                                            'اكتمل الإنشاء!';

                                progressEmbed.setDescription(`\`\`\`js\n[+] ${status}\n\`\`\``)
                                           .setFooter({ text: `${i}%` });

                                // تحديث الرسالة
                                replyPromise = interaction.editReply({ embeds: [progressEmbed] });

                                // Actually create server at appropriate steps
                                if (i === 20) {
                                    // Create basic bot files
                                    await fs.writeFile(path.join(serverPath, 'index.js'), `
const Discord = require('discord.js');
const client = new Discord.Client({
    intents: [
        Discord.GatewayIntentBits.Guilds,
        Discord.GatewayIntentBits.GuildMessages,
        Discord.GatewayIntentBits.MessageContent
    ]
});

client.on('ready', () => {
    console.log(\`تم تسجيل الدخول: \${client.user.tag}\`);
});

client.on('messageCreate', message => {
    if (message.content === '!ping') {
        message.reply('Pong!');
    }
});

client.login(process.env.DISCORD_TOKEN);`);
                                }
                                else if (i === 40) {
                                    await fs.writeFile(path.join(serverPath, 'package.json'), `{
  "name": "${serverName}",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "discord.js": "^14.14.1"
  }
}`);
                                }
                            }

                            // Final success message
                            progressEmbed.setColor('#4fd69c')
                                       .setTitle('✅ تم إنشاء السيرفر')
                                       .setDescription('```js\n[+] تم إنشاء السيرفر بنجاح!\n```')
                                       .setFooter({ text: '100%' });

                            await interaction.editReply({ embeds: [progressEmbed] });

                            // Return to control panel using followUp
                            await interaction.followUp({
                                content: "✨ سيتم العودة إلى لوحة التحكم...",
                                ephemeral: true
                            });
                            
                            // تنظيف الرسائل القديمة وإرسال لوحة تحكم جديدة
                            setTimeout(async () => {
                                try {
                                    // إرسال لوحة تحكم جديدة
                                    const newControlMsg = await interaction.channel.send('!control');
                                    
                                    // إعلام المستخدم بأن اللوحة أصبحت جاهزة
                                    await interaction.followUp({
                                        content: "✅ تم إنشاء السيرفر وتحديث لوحة التحكم بنجاح!",
                                        ephemeral: true
                                    }).catch(() => {});
                                    
                                    // تمرير بضع ثوانٍ لتحديث السيليكت مينو
                                    setTimeout(() => {
                                        if (newControlMsg?.components?.[1]?.components?.[0]) {
                                            // محاولة تحديث القائمة المنسدلة (إذا كانت موجودة)
                                            const selectMenu = newControlMsg.components[1].components[0];
                                            if (selectMenu.type === 'STRING_SELECT') {
                                                // تفعيل حدث نقر على اللوحة لتحديثها بالكامل
                                                newControlMsg.clickButton?.({ customId: 'refresh_servers' }).catch(() => {});
                                            }
                                        }
                                    }, 2000);
                                    
                                } catch (err) {
                                    console.error('Error updating control panel after server creation:', err);
                                }
                            }, 1500);

                        } catch (error) {
                            console.error("Error creating server:", error);
                            
                            // Clean up on error
                            await fs.remove(serverPath).catch(e => console.error("Cleanup error:", e));
                            
                            progressEmbed.setColor('#f16a6a')
                                       .setTitle('❌ فشل إنشاء السيرفر')
                                       .setDescription(`\`\`\`js\n[-] ${error.message}\n\`\`\``)
                                       .setFooter({ text: 'فشل' });

                            await interaction.editReply({ embeds: [progressEmbed] }).catch(e => {
                                console.error("Error updating error message:", e);
                            });
                        }
                    }
                    else if (interaction.customId.startsWith('add_user_modal_')) {
                        const serverName = interaction.customId.replace('add_user_modal_', '');
                        const userId = interaction.fields.getTextInputValue('user_id');

                        // التحقق من صحة معرف المستخدم
                        try {
                            await client.users.fetch(userId);
                        } catch (userError) {
                            return interaction.reply({
                                content: '❌ معرف المستخدم غير صالح',
                                ephemeral: true
                            });
                        }

                        // إضافة المستخدم للسيرفر
                        try {
                            let botUser = await BotUser.findOne({ 
                                botName: serverName,
                                ownerId: message.author.id
                            });

                            if (!botUser) {
                                botUser = new BotUser({
                                    botName: serverName,
                                    ownerId: message.author.id,
                                    allowedUsers: []
                                });
                            }

                            // التحقق من عدم وجود المستخدم مسبقاً
                            if (botUser.allowedUsers.some(user => user.userId === userId)) {
                                return interaction.reply({
                                    content: '❌ هذا المستخدم مضاف بالفعل',
                                    ephemeral: true
                                });
                            }

                            botUser.allowedUsers.push({
                                userId,
                                permissions: {
                                    canEdit: false,
                                    canDelete: false,
                                    canStart: false
                                }
                            });

                            await botUser.save();

                            await interaction.reply({
                                content: `✅ تمت إضافة المستخدم \`${userId}\` إلى السيرفر بنجاح`,
                                ephemeral: true
                            });
                        } catch (dbError) {
                            console.error('Error adding user to database:', dbError);
                            return interaction.reply({
                                content: `❌ حدث خطأ أثناء إضافة المستخدم: ${dbError.message}`,
                                ephemeral: true
                            });
                        }
                    }
                } catch (error) {
                    console.error('Modal submit error:', error);
                    try {
                        await interaction.reply({ 
                            content: `❌ حدث خطأ أثناء معالجة النموذج: ${error.message}`,
                            ephemeral: true 
                        });
                    } catch (replyError) {
                        console.error('Error replying to modal submission:', replyError);
                    }
                }
            });

            collector.on('end', async () => {
                // تنظيف المراجع العالمية
                if (global.activeControlPanels && global.activeControlPanels.has(controlMsg.id)) {
                    global.activeControlPanels.delete(controlMsg.id);
                }
                
                try {
                    const disabledEmbed = new Discord.EmbedBuilder()
                        .setColor('#718096')
                        .setTitle('🎮 لوحة التحكم')
                        .setDescription('**انتهت صلاحية لوحة التحكم**\nاستخدم `!control` مرة أخرى')
                        .setFooter({ 
                            text: message.author.username, 
                            iconURL: message.author.displayAvatarURL() 
                        })
                        .setTimestamp();
                    
                    const disabledRow = new Discord.ActionRowBuilder()
                        .addComponents(
                            new Discord.ButtonBuilder()
                                .setCustomId('expired')
                                .setLabel('انتهت الصلاحية')
                                .setStyle(Discord.ButtonStyle.Secondary)
                                .setDisabled(true)
                        );
                    
                    await controlMsg.edit({
                        embeds: [disabledEmbed],
                        components: [disabledRow]
                    });
                } catch (error) {
                    console.error('Error updating control message on end:', error);
                }
            });
        } catch (error) {
            console.error('Control command error:', error);
            message.reply('عذراً، حدث خطأ أثناء إنشاء لوحة التحكم');
        }
    }

    // Add subscription command
    if (message.content.startsWith('!add')) {
        try {
            // Check if user has admin permissions
            if (!message.member.permissions.has('ADMINISTRATOR')) {
                return message.reply('عذراً، فقط المشرفين يمكنهم استخدام هذا الأمر');
            }

            const args = message.content.split(' ');
            if (args.length !== 3) {
                return message.reply('الرجاء استخدام الأمر بالشكل الصحيح: `!add @user عدد_الايام`');
            }

            // Get user ID from mention
            const mentionedUser = message.mentions.users.first();
            if (!mentionedUser) {
                return message.reply('الرجاء منشن المستخدم بشكل صحيح');
            }

            const days = parseInt(args[2]);
            if (isNaN(days) || days <= 0) {
                return message.reply('الرجاء إدخال عدد أيام صحيح وموجب');
            }

            // Read current subscriptions
            const subsPath = path.join(__dirname, 'subs.json');
            let subs = [];
            if (fs.existsSync(subsPath)) {
                subs = JSON.parse(fs.readFileSync(subsPath, 'utf8'));
            }

            // Calculate subscription dates
            const now = new Date();
            const expiryDate = new Date();
            expiryDate.setDate(now.getDate() + days);

            // Check if user already has subscription
            const existingSubIndex = subs.findIndex(sub => sub.userId === mentionedUser.id);
            
            if (existingSubIndex !== -1) {
                // Update existing subscription
                subs[existingSubIndex] = {
                    userId: mentionedUser.id,
                    startDate: now.toISOString(),
                    expiryDate: expiryDate.toISOString(),
                    days: days
                };
                message.reply(`تم تحديث اشتراك <@${mentionedUser.id}> لمدة ${days} يوم`);
            } else {
                // Add new subscription
                subs.push({
                    userId: mentionedUser.id,
                    startDate: now.toISOString(),
                    expiryDate: expiryDate.toISOString(),
                    days: days
                });
                message.reply(`تم إضافة اشتراك ل <@${mentionedUser.id}> لمدة ${days} يوم`);
            }

            // Save updated subscriptions
            fs.writeFileSync(subsPath, JSON.stringify(subs, null, 2));

        } catch (error) {
            console.error('Error in add command:', error);
            message.reply('حدث خطأ أثناء إضافة الاشتراك');
        }
    }
});
//buy sub
//buy sub


const subscriptionsFile = path.join(__dirname, 'subs.json');
const ownerId = '1170686818224705607';
const probotId = '282859044593598464';
const verificationTime = 60000; // 60 ثانية

client.once('ready', () => {
    console.log(`🤖 AI Bot جاهز: ${client.user.tag}`);
    setInterval(removeExpiredSubscriptions, 1000); // التحقق كل ثانية
});

// عند استخدام الأمر !buy
client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    if (message.content === "!buy") {
        let subscriptions = fs.existsSync(subscriptionsFile) ? fs.readJsonSync(subscriptionsFile) : [];
        const userSubscription = subscriptions.find(sub => sub.userId === message.author.id);
        let embed = new Discord.EmbedBuilder().setColor("Blue");

        if (userSubscription) {
            const expiryDate = new Date(userSubscription.expiryDate);
            const remainingTime = (expiryDate - new Date()) / (1000 * 60 * 60 * 24); // بالأيام

            if (remainingTime > 1) {
                embed.setTitle("📅 اشتراكك نشط!")
                     .setDescription(`✅ لديك اشتراك نشط حتى **${expiryDate.toLocaleDateString()}**.\n🕒 لا يمكنك التجديد الآن.`)
                     .setColor("Green");
                return message.reply({ embeds: [embed] });
            }

            embed.setTitle("🔄 تجديد الاشتراك")
                 .setDescription("يمكنك تجديد اشتراكك لمدة **7 أيام** مقابل **10526316**.")
                 .setColor("Green");

            const renewButton = new Discord.ButtonBuilder()
                .setCustomId("renew_subscription")
                .setLabel("تجديد 7 أيام - 10526316")
                .setStyle(Discord.ButtonStyle.Success);

            const buttonrow = new Discord.ActionRowBuilder().addComponents(renewButton);
            return message.reply({ embeds: [embed], components: [buttonrow] });
        }

        embed.setTitle("💳 شراء اشتراك")
             .setDescription("يرجى اختيار مدة الاشتراك:");

        const selectMenu = new Discord.StringSelectMenuBuilder()
            .setCustomId("select_subscription_duration")
            .setPlaceholder("اختر مدة الاشتراك")
            .addOptions(
                new Discord.StringSelectMenuOptionBuilder().setLabel("أسبوع - 10m").setValue("7"),
                new Discord.StringSelectMenuOptionBuilder().setLabel("شهر - 50m").setValue("30")
            );

        const buttonrow = new Discord.ActionRowBuilder().addComponents(selectMenu);
        await message.reply({ embeds: [embed], components: [buttonrow] });
    }
});

// عند اختيار مدة الاشتراك أو تجديده
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isStringSelectMenu() && !interaction.isButton()) return;

    const userId = interaction.user.id;
    let durationDays, amountRequired;

    if (interaction.isStringSelectMenu() && interaction.customId === "select_subscription_duration") {
        durationDays = parseInt(interaction.values[0]);
        amountRequired = durationDays === 7 ? 1000000 : 5000000;
    } else if (interaction.isButton() && interaction.customId === "renew_subscription") {
        durationDays = 7;
        amountRequired = 1000000;
    } else {
        return;
    }

    const embed = new Discord.EmbedBuilder()
        .setTitle("💰 تحويل المبلغ")
        .setDescription(`يرجى تحويل **${amountRequired}** إلى <@!${ownerId}> خلال **60 ثانية**.

- 
يرجى علم عند تحويل قم بتخويل بضريبة 
لشراء اسبوعي :
#credit @vb_dw 10526316
- لشراء شهري حول :
#credit @vb_dw 52631579`);
       

    await interaction.update({ embeds: [embed], components: [] });

    const filter = (message) =>
        message.author.id === probotId &&
        message.channel.id === interaction.channelId &&
        message.content.includes(`has transferred \`$${amountRequired}\` to <@!${ownerId}>`);

    try {
        const collected = await interaction.channel.awaitMessages({ filter, max: 1, time: verificationTime, errors: ["time"] });
        const transactionMessage = collected.first();

        if (transactionMessage) {
            if (interaction.customId === "renew_subscription") {
                renewSubscription(userId, durationDays);
                embed.setTitle("✅ تجديد ناجح!")
                     .setDescription(`تم **تجديد** اشتراكك لمدة **${durationDays} يومًا**.`)
                     .setColor("Green");
            } else {
                addSubscription(userId, durationDays);
                embed.setTitle("✅ اشتراك ناجح!")
                     .setDescription(`تم **إضافة** اشتراك لمدة **${durationDays} يومًا**.`)
                     .setColor("Green");
            }
            await interaction.editReply({ embeds: [embed], components: [] });
        }
    } catch (error) {
        embed.setTitle("❌ فشل الدفع")
             .setDescription("⏳ انتهى الوقت ولم يتم العثور على عملية تحويل.")
             .setColor("Red");
        await interaction.editReply({ embeds: [embed], components: [] });
    }
});

// إضافة اشتراك جديد
function addSubscription(userId, days) {
    let subscriptions = fs.existsSync(subscriptionsFile) ? fs.readJsonSync(subscriptionsFile) : [];
    
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days);

    subscriptions.push({
        userId: userId,
        expiryDate: expiryDate.toISOString(),
        days: days
    });

    fs.writeJsonSync(subscriptionsFile, subscriptions, { spaces: 4 });
}

// تجديد الاشتراك
function renewSubscription(userId, days) {
    let subscriptions = fs.existsSync(subscriptionsFile) ? fs.readJsonSync(subscriptionsFile) : [];
    
    const userSubscription = subscriptions.find(sub => sub.userId === userId);
    if (userSubscription) {
        let expiryDate = new Date(userSubscription.expiryDate);
        expiryDate.setDate(expiryDate.getDate() + days);
        userSubscription.expiryDate = expiryDate.toISOString();
    } else {
        addSubscription(userId, days);
    }

    fs.writeJsonSync(subscriptionsFile, subscriptions, { spaces: 4 });
}

// إزالة الاشتراكات المنتهية
function removeExpiredSubscriptions() {
    if (!fs.existsSync(subscriptionsFile)) return;
    
    let subscriptions = fs.readJsonSync(subscriptionsFile);
    const now = new Date();
    
    const validSubscriptions = subscriptions.filter(sub => new Date(sub.expiryDate) > now);

    if (validSubscriptions.length !== subscriptions.length) {
        fs.writeJsonSync(subscriptionsFile, validSubscriptions, { spaces: 4 });
        console.log("📌 تم حذف الاشتراكات المنتهية.");
    }
}







   
       












    


   


// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('Client connected');

    // Send bot status updates
    const sendBotStatus = async () => {
        const statuses = {};
        for (const [key, value] of processes.entries()) {
            statuses[key] = {
                isRunning: true,
                output: value.output
            };
        }
        socket.emit('botStatuses', statuses);
    };

    // Send initial status
    sendBotStatus();

    // When client specifically requests statuses
    socket.on('getStatuses', () => {
        sendBotStatus();
    });

    socket.on('startBot', async (data) => {
        try {
            const { processKey } = data;
            const [userId, serverName] = processKey.split('-');
            console.log(`Socket requested start bot: ${serverName} for user ${userId}`);
            await startServer(serverName, userId);
            socket.emit('botStatus', { processKey, isRunning: true });
        } catch (error) {
            console.error('Start bot error:', error);
            socket.emit('botError', { error: error.message });
        }
    });

    socket.on('stopBot', async (data) => {
        try {
            const { processKey } = data;
            const [userId, serverName] = processKey.split('-');
            console.log(`Socket requested stop bot: ${serverName} for user ${userId}`);
            const processData = processes.get(processKey);
            if (processData) {
                processData.process.kill();
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });
            } else {
                console.log(`No process found for ${processKey}`);
            }
        } catch (error) {
            console.error('Stop bot error:', error);
            socket.emit('botError', { error: error.message });
        }
    });

    socket.on('setAutoReconnect', async (data) => {
        try {
            const { processKey, enabled } = data;
            const [userId, serverName] = processKey.split('-');
            let botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
            if (botUser) {
                botUser.autoReconnect = enabled;
                await botUser.save();
                socket.emit('autoReconnectUpdated', { success: true });
            } else {
                // إنشاء سجل جديد إذا لم يكن موجوداً
                botUser = new BotUser({
                    botName: serverName,
                    ownerId: userId,
                    allowedUsers: [],
                    autoReconnect: enabled
                });
                await botUser.save();
                socket.emit('autoReconnectUpdated', { success: true });
            }
        } catch (error) {
            console.error('Auto reconnect error:', error);
            socket.emit('botError', { error: error.message });
        }
    });

    // Send status updates every 5 seconds
    const statusInterval = setInterval(sendBotStatus, 5000);

    socket.on('disconnect', () => {
        clearInterval(statusInterval);
        console.log('Client disconnected');
    });

    // Send initial status
    socket.on('getBotStatus', (processKey) => {
        console.log(`Status requested for process: ${processKey}`);
        io.emit('botStatus', {
            processKey,
            isRunning: processes.has(processKey)
        });
    });

    // إضافة استجابة للحصول على قائمة الملفات
    socket.on('getFilesList', async (data) => {
        try {
            const { serverName, filePath = '' } = data;
            const userId = socket.request.session?.passport?.user?.id;

            if (!userId) {
                socket.emit('filesError', { error: 'غير مصرح لك' });
                return;
            }

            console.log(`Socket requested files for ${serverName}, path: ${filePath}`);

            const dirPath = path.join(__dirname, 'uploads', userId, serverName, filePath);

            if (!await fs.pathExists(dirPath)) {
                await fs.ensureDir(dirPath);
            }

            const files = await fs.readdir(dirPath);
            const fileDetails = await Promise.all(files.map(async (file) => {
                const fullFilePath = path.join(dirPath, file);
                const stats = await fs.stat(fullFilePath);
                return {
                    name: file,
                    isDirectory: stats.isDirectory(),
                    size: stats.size,
                    modified: stats.mtime
                };
            }));

            socket.emit('filesList', { success: true, files: fileDetails });
        } catch (error) {
            console.error('Error getting files via socket:', error);
            socket.emit('filesError', { error: error.message });
        }
    });
});

// API endpoint to get all bot statuses
app.get('/api/bot-statuses', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const statuses = {};
        for (const [key, value] of processes.entries()) {
            statuses[key] = {
                isRunning: true,
                startTime: value.startTime
            };
        }

        res.json({ success: true, statuses });
    } catch (error) {
        console.error('Error getting bot statuses:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});


// Update permission management endpoints
app.post('/api/bot/permissions/update', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ successfalse, error: 'Unauthorized' });
    }

    try {
        const { botName, userId, permission, value } = req.body;
        const ownerId = req.user.id;

        const botUser = await BotUser.findOne({ botName, ownerId });
        if (!botUser) {
            return res.json({ success: false, error: 'Bot not found' });
        }

        const userIndex = botUser.allowedUsers.findIndex(user => user.userId === userId);
        if (userIndex === -1) {

            return res.json({ success: false, error: 'User not found' });
        }

        botUser.allowedUsers[userIndex].permissions[permission] = value;
        await botUser.save();

        console.log(`Updated permissions for user ${userId} on bot ${botName}: ${permission} = ${value}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Permission update error:', error);
        res.json({ success: false, error: error.message });
    }
});

// Update user add endpoint to include permissions
app.post('/api/bot/users/add', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { botName, userId, permissions } = req.body;
        const ownerId = req.user.id;

        let botUser = await BotUser.findOne({ botName, ownerId });
        if (!botUser) {
            botUser = new BotUser({
                botName,
                ownerId,
                allowedUsers: []
            });
        }

        if (!botUser.allowedUsers.find(user => user.userId === userId)) {
            botUser.allowedUsers.push({
                userId,
                permissions: permissions || {
                    canEdit: false,
                    canDelete: false,
                    canStart: false
                }
            });
            await botUser.save();
        }

        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// API للحصول على قائمة المستخدمين المشتركين
app.get('/api/bot/users/:botName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { botName } = req.params;
        const ownerId = req.user.id;

        const botUser = await BotUser.findOne({ botName, ownerId });
        if (!botUser) {
            return res.json({ success: true, users: [] });
        }

        const users = botUser.allowedUsers || [];
        res.json({ success: true, users });
    } catch (error) {
        console.error('Error getting users:', error);
        res.json({ success: false, error: error.message });
    }
});

// Update user remove endpoint
app.post('/api/bot/users/remove', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    try {
        const { botName, userId } = req.body;
        const ownerId = req.user.id;

        const botUser = await BotUser.findOne({ botName, ownerId });
        if (botUser) {
            botUser.allowedUsers = botUser.allowedUsers.filter(user => user.userId !== userId);
            await botUser.save();
        }

        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// Update the server control routes to check permissions

// Apply permission check to relevant routes
// New file management routes from edited snippet
app.get('/api/server/:serverName/files', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول إلى الملفات' });
    }

    try {
        console.log("Server files API called:", req.params, req.query); // سجل للتشخيص
        const { serverName } = req.params;
        const reqPath = req.query.path || '';
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const dirPath = path.join(__dirname, 'uploads', userId, serverName, reqPath);

        console.log("Looking for files in path:", dirPath);

        // التأكد من وجود المجلد وإنشائه إذا لم يكن موجوداً
        if (!await fs.pathExists(dirPath)) {
            console.log("Directory not found, creating it:", dirPath);
            try {
                await fs.ensureDir(dirPath);
                console.log("Directory created successfully");
            } catch (mkdirErr) {
                console.error("Failed to create directory:", mkdirErr);
                return res.json({ success: false, error: 'فشل في إنشاء المجلد' });
            }
        }

        // محاولة قراءة محتويات المجلد
        let files = [];
        try {
            files = await fs.readdir(dirPath);
            console.log("Files found:", files.length);
        } catch (readErr) {
            console.error("Error reading directory:", readErr);
            return res.json({ success: false, error: 'خطأ في قراءة محتويات المجلد: ' + readErr.message });
        }

        // جمع تفاصيل الملفات مع معالجة الأخطاء
        const fileDetails = [];
        for (const file of files) {
            try {
                const filePath = path.join(dirPath, file);
                const stats = await fs.stat(filePath);
                fileDetails.push({
                    name: file,
                    isDirectory: stats.isDirectory(),
                    size: stats.size,
                    modified: stats.mtime
                });
            } catch (statErr) {
                console.error("Error getting stats for file " + file + ":", statErr);
                // إضافة الملف مع معلومات افتراضية إذا لم يمكن قراءة معلوماته
                fileDetails.push({
                    name: file,
                    isDirectory: false,
                    size: 0,
                    modified: new Date(),
                    error: 'خطأ في قراءة معلومات الملف'
                });
            }
        }

        console.log("Returning file details for", fileDetails.length, "files");
        res.json({ success: true, files: fileDetails });
    } catch (error) {
        console.error('Get files error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/server/:serverName/file', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لإنشاء ملفات' });
    }

    try {
        const { serverName } = req.params;
        const { path: filePath, content = '' } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const fullPath = path.join(__dirname, 'uploads', userId, serverName, filePath);

        if (await fs.pathExists(fullPath)) {
            return res.json({ success: false, error: 'الملف موجود بالفعل' });
        }

        await fs.writeFile(fullPath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        console.error('Create file error:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/server/:serverName/folder', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لإنشاء مجلدات' });
    }

    try {
        const { serverName } = req.params;
        const { path: folderPath } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const fullPath = path.join(__dirname, 'uploads', userId, serverName, folderPath);

        if (await fs.pathExists(fullPath)) {
            return res.json({ success: false, error: 'المجلد موجود بالفعل' });
        }

        await fs.mkdir(fullPath);
        res.json({ success: true });
    } catch (error) {
        console.error('Create folder error:',error);
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/server/:serverName/file/:fileName/download', checkServerAccess, async (req, res) => {
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).json({ success: false, error: 'الملف غير موجود' });
        }

        console.log('Downloading file:', filePath);
        res.download(filePath);
    } catch (error) {
        console.error('Download file error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/server/:serverName/file/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول إلى الملفات' });
    }

    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        console.log('Attempting to read file:', filePath);

        if (!await fs.pathExists(filePath)) {
            console.log('File not found:', filePath);
            return res.json({ success: false, error: 'الملف غير موجود' });
        }

        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            console.log('Requested path is a directory, not a file');
            return res.status(400).json({ success: false, error: 'لا يمكن تحميل المجلدات' });
        }

        try {
            // محاولة قراءة الملف باستخدام fs.promises
            const content = await fs.promises.readFile(filePath, 'utf8').catch(err => {
                console.error('Error with promises readFile:', err);
                return null;
            });

            if (content !== null) {
                console.log('File read successfully with promises, content length:', content.length);
                return res.json({ success: true, content });
            }

            // إذا فشلت الطريقة الأولى، جرب الطريقة التقليدية
            fs.readFile(filePath, { encoding: 'utf8' }, (err, data) => {
                if (err) {
                    console.error('Error with callback readFile:', err);

                    // محاولة أخيرة بقراءة الملف كبيانات ثنائية ثم تحويلها لنص
                    fs.readFile(filePath, (binaryErr, binaryData) => {
                        if (binaryErr) {
                            console.error('Error with binary readFile:', binaryErr);
                            return res.status(500).json({ success: false, error: 'فشل في قراءة الملف بعد عدة محاولات' });
                        }
                        try {
                            const binaryContent = binaryData.toString('utf8');
                            console.log('File read as binary and converted to string, length:', binaryContent.length);
                            return res.json({ success: true, content: binaryContent });
                        } catch (convErr) {
                            console.error('Error converting binary to string:', convErr);
                            return res.status(500).json({ success: false, error: 'فشل في تحويل محتوى الملف' });
                        }
                    });
                } else {
                    console.log('File read successfully with callback, content length:', data.length);
                    return res.json({ success: true, content: data });
                }
            });
        } catch (readError) {
            console.error('General error reading file content:', readError);
            return res.status(500).json({ success: false, error: `فشل في قراءة الملف: ${readError.message}` });
        }
    } catch (error) {
        console.error('File read error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// إضافة مسار لقراءة محتوى الملفات (الطريقة الجديدة)
app.get('/api/server/:serverName/file-content', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const { path: filePath = '' } = req.query;
        
        if (!filePath) {
            return res.status(400).json({ success: false, error: 'مسار الملف مطلوب' });
        }
        
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const fullPath = path.join(__dirname, 'uploads', userId, serverName, filePath);
        
        if (!await fs.pathExists(fullPath)) {
            return res.status(404).json({ success: false, error: 'الملف غير موجود' });
        }
        
        const stats = await fs.stat(fullPath);
        if (stats.isDirectory()) {
            return res.status(400).json({ success: false, error: 'المسار المحدد هو مجلد وليس ملفًا' });
        }
        
        const content = await fs.readFile(fullPath, 'utf8');
        return res.send(content);
    } catch (error) {
        console.error('Error reading file:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// إضافة مسار بديل لقراءة محتوى الملفات (الطريقة القديمة)
app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول إلى الملفات' });
    }

    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const fullPath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        console.log('Alternative method - Reading file:', fullPath);

        if (!await fs.pathExists(fullPath)) {
            return res.status(404).send('الملف غير موجود');
        }

        const stats = await fs.stat(fullPath);
        if (stats.isDirectory()) {
            return res.status(400).send('لا يمكن قراءة المجلدات');
        }

        const content = await fs.readFile(fullPath, 'utf8');
        res.send(content);
    } catch (error) {
        console.error('Alternative file read error:', error);
        res.status(500).send(error.message);
    }
});

// Remove the stray closing brace at the end

// Server start/stop functions
const startServer = async (serverName, userId) => {
    console.log("Starting server " + serverName + " for user " + userId);
    const serverPath = path.join(__dirname, 'uploads', userId, serverName);
    const mainFile = await findMainFile(serverPath);

    if (!mainFile) {
        throw new Error('ملف التشغيل الرئيسي غير موجود');
    }

    const processKey = userId + "-" + serverName;
    if (processes.has(processKey)) {
        console.warn(`Server ${serverName} already running`);
        return;
    }

    console.log(`Starting process with main file: ${mainFile}`);

    // تهيئة متغيرات البيئة مع بورت ثابت
    const customEnv = { 
        ...process.env,
        PORT: 21163 // بورت ثابت على 3000
    };

    console.log(`Using PORT: ${customEnv.PORT} for ${serverName}`);

    const childProcess = spawn('node', [mainFile], {
        cwd: serverPath,
        env: customEnv
    });

    processes.set(processKey, {
        process: childProcess,
        output: [],
        startTime: Date.now(),
        port: customEnv.PORT
    });

    childProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log(`[${serverName}] stdout:`, output);
        const processData = processes.get(processKey);
        if (processData) {
            processData.output.push(output);
            io.emit('botOutput', { processKey, output });
        }
    });

    childProcess.stderr.on('data', (data) => {
        const output = data.toString();
        console.error(`[${serverName}] stderr:`, output);
        const processData = processes.get(processKey);
        if (processData) {
            processData.output.push(output);
            io.emit('botOutput', { processKey, output });
        }
    });

    childProcess.on('close', async (code) => {
        console.log(`[${serverName}] Process closed with code ${code}`);
        processes.delete(processKey);
        io.emit('botStatus', { processKey, isRunning: false });

        const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
        if (botUser && botUser.autoReconnect) {
            console.log(`Auto reconnecting bot: ${serverName}`);
            setTimeout(() => {
                startServer(serverName, userId);
            }, 5000);
        }
    });

    io.emit('botStatus', { processKey, isRunning: true });
};

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لتشغيل السيرفر' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        await startServer(serverName, userId);
        
        // إرسال إشعار عبر الويبهوك عن بدء تشغيل السيرفر
        await sendWebhookNotification(userId, serverName, 'تشغيل السيرفر', {
            'الحالة': 'تم التشغيل بنجاح',
            'وقت التشغيل': new Date().toLocaleString('ar-SA'),
            'بواسطة': req.user.username || 'مستخدم غير معروف'
        }).catch(err => console.error('Webhook notification error:', err));
        
        res.json({ success: true });
    } catch (error) {
        console.error('Start server error:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لإيقاف السيرفر' });
    }

    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (!processData) {
            return res.json({ success: false, error: 'السيرفر متوقف بالفعل' });
        }

        processData.process.kill();
        processes.delete(processKey);
        io.emit('botStatus', { processKey, isRunning: false });
        
        // إرسال إشعار عبر الويبهوك عن إيقاف السيرفر
        await sendWebhookNotification(userId, serverName, 'إيقاف السيرفر', {
            'الحالة': 'تم الإيقاف بنجاح',
            'وقت الإيقاف': new Date().toLocaleString('ar-SA'),
            'بواسطة': req.user.username || 'مستخدم غير معروف',
            'مدة التشغيل': processData.startTime ? 
                Math.floor((Date.now() - processData.startTime) / 1000 / 60) + ' دقيقة' : 'غير معروف'
        }).catch(err => console.error('Webhook notification error:', err));
        
        res.json({ success: true });
    } catch (error) {
        console.error('Stop server error:', error);
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (processData) {
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Server is not running' });
        }
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (processData) {
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Server is not running' });
        }
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (processData) {
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Server is not running' });
        }
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (processData) {
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Server is not running' });
        }
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/stop-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const processKey = userId + "-" + serverName;

        const processData = processes.get(processKey);
        if (processData) {
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Server is not running' });
        }
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to read files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).send('File not found');
        }

        const content = await fs.readFile(filePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/save-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to edit files' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { content } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        await fs.writeFile(filePath, content, 'utf8');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.post('/api/start-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canStart) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to start server' });
    }
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const mainFile = await findMainFile(serverPath);

        if (!mainFile) {
            return res.json({ success: false, error: 'Main file not found' });
        }

        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            return res.json({ success: false, error: 'Server is already running' });
        }

        const startBot = () => {
            const process = spawn('node', [mainFile], {
                cwd: serverPath
            });

            processes.set(processKey, {
                process,
                output: [],
                startTime: Date.now()
            });

            process.stdout.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.stderr.on('data', (data) => {
                const output = data.toString();
                const processData = processes.get(processKey);
                if (processData) {
                    processData.output.push(output);
                    io.emit('botOutput', { processKey, output });
                }
            });

            process.on('close', async (code) => {
                processes.delete(processKey);
                io.emit('botStatus', { processKey, isRunning: false });

                // Check if auto reconnect is enabled
                const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
                if (botUser && botUser.autoReconnect) {
                    console.log(`Auto reconnecting bot: ${serverName}`);
                    setTimeout(startBot, 5000); // Retry after 5 seconds
                }
            });

            io.emit('botStatus', { processKey, isRunning: true });
        };

        startBot();

        res.json({
            success: true,
            processKey,
            output: 'Server started successfully'
        });
    } catch (error) {
        console.error('Error starting server:', error);
        res.json({ success: false, error: error.message });
    }
});

// مسار لتدفق مخرجات السيرفر
app.get('/api/stream-output/:processKey', (req, res) => {
    const { processKey } = req.params;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const processData = processes.get(processKey);
    if (processData) {
        const { output } = processData;
        if (output.length > 0) {
            res.write(`data: ${JSON.stringify(output.join('\n'))}\n\n`);
            output.length = 0;
        }
    }

    const interval = setInterval(() => {
        const processData = processes.get(processKey);
        if (processData) {
            const { output } = processData;
            if (output.length > 0) {
                res.write(`data: ${JSON.stringify(output.join('\n'))}\n\n`);
                output.length = 0;
            }
        }
    }, 1000);

    req.on('close', () => {
        clearInterval(interval);
    });
});

// واجهة برمجة التطبيقات لتنزيل ملف
app.get('/api/download-file/:serverName/:filePath(*)', checkServerAccess, async (req, res) => {
    try {
        const { serverName, filePath } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const fullFilePath = path.join(serverPath, filePath);

        // تأكدمن أن المسار آمن (لمنع directory traversal)
        const normalizedPath = path.normalize(fullFilePath);
        if (!normalizedPath.startsWith(serverPath)) {
            return res.status(403).send('مسار غير مسموح به');
        }

        // التحقق من وجود الملف
        if (!await fs.pathExists(normalizedPath)) {
            return res.status(404).send('الملف غير موجود');
        }

        // التحقق من أن الملف ليس مجلداً
        const stats = await fs.stat(normalizedPath);
        if (stats.isDirectory()) {
            return res.status(400).send('لا يمكن تنزيل المجلدات');
        }

        // إرسال الملف للتنزيل
        res.download(normalizedPath);
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).send('حدث خطأ أثناء تنزيل الملف');
    }
});

// مسار حذف الملفات 
app.post('/api/delete-server/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canDelete) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions to delete server' });
    }
    try {
        const serverName = decodeURIComponent(req.params.serverName);
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

        // التحقق من وجود السيرفر
        const exists = await fs.pathExists(serverPath);
        if (!exists) {
            return res.json({ success: false, error: 'السيرفر غير موجود' });
        }

        // إيقاف السيرفر إذا كان قيد التشغيل
        const processKey = userId + "-" + serverName;
        if (processes.has(processKey)) {
            const processData = processes.get(processKey);
            processData.process.kill('SIGTERM');
            processes.delete(processKey);
        }

        // حذف مجلد السيرفر
        await fs.remove(serverPath);

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting server:', error);
        res.json({ success: false, error: 'حدث خطأ أثناء حذف السيرفر' });
    }
});

app.delete('/delete-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canDelete) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لحذف الملفات' });
    }
    try {
        const { serverName, fileName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        // التحقق من وجود الملف
        if (!await fs.pathExists(filePath)) {
            return res.json({ success: false, error: 'الملف غير موجود' });
        }

        // حذف الملف
        await fs.remove(filePath);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.json({ success: false, error: error.message });
    }
});

// مسار إنشاء سيرفر جديد
app.post('/create-server', upload.single('serverFile'), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

    try {
        const { serverName } = req.body;
        const userId = req.user.id;

        // التحقق من اسم السيرفر
        if (!serverName || !/^[\u0600-\u06FFa-zA-Z0-9-_]+$/.test(serverName)) {
            if (req.file) await fs.unlink(req.file.path).catch(console.error);
            return res.render('create-server', {
                user: req.user,
                error: 'اسم السيرفر غير صالح. يمكن استخدام الحروف العربية والإنجليزية والأرقام والشرطات فقط'
            });
        }

        // التحقق من الاشتراك وعدد السيرفرات المسموح بها
        const subsData = await fs.readJSON('subs.json').catch(() => []);
        const userSub = subsData.find(sub => sub.userId === userId);
        const isSubscribed = userSub && new Date(userSub.expiryDate) > new Date();
        
        // تحديد الحد الأقصى بناءً على الاشتراك
        const maxServers = isSubscribed ? 5 : 2;
        
        const uploadPath = path.join(__dirname, 'uploads', userId);
        let serverCount = 0;

        if (await fs.pathExists(uploadPath)) {
            const items = await fs.readdir(uploadPath);
            serverCount = items.filter(item => {
                try {
                    return fs.statSync(path.join(uploadPath, item)).isDirectory();
                } catch (err) {
                    console.error(`Error checking directory ${item}:`, err);
                    return false;
                }
            }).length;
        }

        if (serverCount >= maxServers) {
            if (req.file) await fs.unlink(req.file.path).catch(console.error);
            return res.render('create-server', {
                user: req.user,
                error: `لقد وصلت للحد الأقصى من البوتات (${serverCount}/${maxServers}).${!isSubscribed ? ' قم بترقية حسابك للحصول على المزيد.' : ''}`,
                isSubscribed: isSubscribed
            });
        }

        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

        // التحقق من وجود السيرفر مسبقاً
        if (await fs.pathExists(serverPath)) {
            if (req.file) await fs.unlink(req.file.path).catch(console.error);
            return res.render('create-server', {
                user: req.user,
                error: 'يوجد سيرفر بهذا الاسم مسبقاً'
            });
        }

        // إنشاء مجلد السيرفر
        await fs.ensureDir(serverPath);

        // تحديد سلوك مختلف بناءً على وجود ملف أو لا
        if (req.file) {
            // معالجة حالة وجود ملف ZIP
            try {
                // فك ضغط الملف
                const extract = require('extract-zip');
                await extract(req.file.path, { dir: serverPath });
                await fs.unlink(req.file.path);
            } catch (extractError) {
                console.error('Error extracting ZIP file:', extractError);
                await fs.remove(serverPath).catch(console.error);
                return res.render('create-server', {
                    user: req.user,
                    error: 'فشل في فك ضغط الملف: ' + extractError.message
                });
            }
        } else {
            // إنشاء سيرفر فارغ مع ملف index.js بسيط
            try {
                const defaultIndexContent = `// بوت ديسكورد بسيط
const Discord = require('discord.js');
const client = new Discord.Client({ intents: [
  'Guilds',
  'GuildMessages',
  'MessageContent',
  'GuildMembers'
]});

// تسجيل الدخول للبوت
client.on('ready', () => {
  console.log(\`تم تسجيل الدخول كـ \${client.user.tag}!\`);
});

// الرد على الرسائل
client.on('messageCreate', msg => {
  if (msg.content === '!ping') {
    msg.reply('Pong!');
  }
});

// قم بتوكن البوت الخاص بك
client.login(process.env.TOKEN || 'ضع_توكن_البوت_هنا');
`;
                await fs.writeFile(path.join(serverPath, 'index.js'), defaultIndexContent, 'utf8');
                
                // إنشاء ملف package.json أساسي
                const packageJsonContent = `{
  "name": "${serverName}",
  "version": "1.0.0",
  "description": "Discord Bot",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "discord.js": "^14.11.0"
  }
}`;
                await fs.writeFile(path.join(serverPath, 'package.json'), packageJsonContent, 'utf8');
            } catch (createFileError) {
                console.error('Error creating default files:', createFileError);
                await fs.remove(serverPath).catch(console.error);
                return res.render('create-server', {
                    user: req.user,
                    error: 'فشل في إنشاء ملفات افتراضية للسيرفر: ' + createFileError.message
                });
            }
        }

        // تحديث عدد السيرفرات
        await UserServerCount.findOneAndUpdate(
            { userId: userId },
            { $inc: { count: 1 } },
            { upsert: true }
        );

        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error creating server:', error);
        if (req.file) {
            await fs.unlink(req.file.path).catch(console.error);
        }
        res.render('create-server', {
            user: req.user,
            error: 'حدث خطأ أثناء إنشاء السيرفر: ' + error.message
        });
    }
});

// API endpoint to get files in a directory
app.get('/api/files/:serverName/:directory?', checkServerAccess, async (req, res) => {
    try {
        const { serverName, directory = '' } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        const directoryPath = directory ? path.join(serverPath, directory) : serverPath;

        // تأكد من أن المسار آمن (لمنع directory traversal)
        const normalizedPath = path.normalize(directoryPath);
        if (!normalizedPath.startsWith(serverPath)) {
            return res.status(403).json({ success: false, error: 'مسار غير مسموح به' });
        }

        if (!await fs.pathExists(normalizedPath)) {
            return res.status(404).json({ success: false, error: 'المسار غير موجود' });
        }

        // Make sure we have read permissions for the directory
        try {
            await fs.access(normalizedPath, fs.constants.R_OK);
        } catch (accessError) {
            return res.status(403).json({ success: false, error: 'لا يمكن الوصول إلى الملفات في هذا المجلد' });
        }

        const entries = await fs.readdir(normalizedPath, { withFileTypes: true });
        const files = entries.map(entry => {
            const isDirectory = entry.isDirectory();
            return {
                name: entry.name,
                isDirectory: isDirectory,
                type: isDirectory ? 'directory' : path.extname(entry.name).slice(1) || 'file'
            };
        });

        res.json(files);
    } catch (error) {
        console.error('Error listing files:', error);
        res.status(500).json({ success: false, error: 'حدث خطأ أثناء قراءة الملفات' });
    }
});

// نقطة نهاية جديدة للحصول على جميع ملفات السيرفر بشكل متكرر (تظل كما هي للتوافق)
app.get('/api/list-server-files/:serverName', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

        if (!await fs.pathExists(serverPath)) {
            return res.status(404).json({ success: false, error: 'السيرفر غير موجود' });
        }

        // دالة متكررة لقراءة جميع الملفات في المجلد والمجلدات الفرعية
        const getAllFiles = async (dir, relativePath = '') => {
            const entries = await fs.readdir(dir, { withFileTypes: true });

            let files = [];
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                const entryRelativePath = path.join(relativePath, entry.name);
                if (entry.isDirectory()) {
                    // استدعاء متكرر للمجلدات الفرعية
                    files.push({
                        name: entry.name,
                        path: entryRelativePath,
                        isDirectory: true,
                        modified: (await fs.stat(fullPath)).mtime
                    });

                    const subDirFiles = await getAllFiles(fullPath, entryRelativePath);
                    files = [...files, ...subDirFiles];
                } else {
                    // إضافة الملف مع مساره النسبي
                    const stats = await fs.stat(fullPath);
                    files.push({
                        name: entry.name,
                        path: entryRelativePath,
                        size: stats.size,
                        isDirectory: false,
                        modified: stats.mtime
                    });
                }
            }

            return files;
        };

        const allFiles = await getAllFiles(serverPath);
        res.json({ success: true, files: allFiles });

    } catch (error) {
        console.error('Error listing server files:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// File Management Routes
app.get('/get-files/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول إلى الملفات' });
    }

    try {
        const { serverName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);

        if (!await fs.pathExists(serverPath)) {
            return res.json({ success: false, error: 'المجلد غير موجود' });
        }

        const files = await fs.readdir(serverPath);
        const fileDetails = await Promise.all(files.map(async file => {
            const stats = await fs.stat(path.join(serverPath, file));
            return {
                name: file,
                isDirectory: stats.isDirectory(),
                size: stats.size,
                createdAt: stats.birthtime
            };
        }));

        res.json({
            success: true,
            files: fileDetails
        });
    } catch (error) {
        console.error('Error getting files:', error);
        res.json({ success: false, error: error.message });
    }
});

app.post('/upload-file', upload.single('file'), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }
    
    try {
        if (!req.file) {
            return res.json({ success: false, error: 'لم يتم تحديد ملف' });
        }

        const { serverName, path: uploadPath = '' } = req.body;
        const userId = req.user.id;
        
        // التحقق من وجود المعرف وملكية السيرفر
        let isOwner = true;
        let ownerId = userId;
        
        // التحقق مما إذا كان المستخدم ليس المالك
        const botUser = await BotUser.findOne({
            botName: serverName,
            'allowedUsers.userId': userId
        });
        
        if (botUser) {
            isOwner = false;
            ownerId = botUser.ownerId;
            
            // التحقق من صلاحيات المستخدم
            const userPermission = botUser.allowedUsers.find(user => user.userId === userId);
            if (!userPermission?.permissions?.canEdit) {
                await fs.remove(req.file.path);
                return res.json({ success: false, error: 'ليس لديك صلاحية لرفع الملفات' });
            }
        }

        const serverPath = path.join(__dirname, 'uploads', ownerId, serverName);
        const targetPath = path.join(serverPath, uploadPath);
        
        // التأكد من وجود المجلد الهدف
        await fs.ensureDir(targetPath);
        
        // نقل الملف المرفوع إلى المكان الصحيح
        await fs.move(req.file.path, path.join(targetPath, req.file.originalname), { overwrite: true });
        
        console.log(`File uploaded successfully: ${req.file.originalname} to ${targetPath}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error uploading file:', error);
        if (req.file && req.file.path) {
            await fs.remove(req.file.path).catch(err => console.error('Error removing temp file:', err));
        }
        res.json({ success: false, error: error.message });
    }
});

app.post('/create-folder', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لإنشاء المجلدات' });
    }

    try {
        const { serverName, folderName } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const folderPath = path.join(__dirname, 'uploads', userId, serverName, folderName);

        // Validate folder name
        if (!folderName || /[<>:"/\\|?*]/.test(folderName)) {
            return res.json({ success: false, error: 'اسم المجلد غير صالح' });
        }

        await fs.ensureDir(folderPath);
        res.json({ success: true });
    } catch (error) {
        console.error('Error creating folder:', error);
        res.json({ success: false, error: error.message });
    }
});

app.delete('/delete-file/:serverName/:fileName(*)', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canDelete) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لحذف الملفات' });
    }
    try {
        const { serverName, fileName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        // التحقق من وجود الملف
        if (!await fs.pathExists(filePath)) {
            return res.json({ success: false, error: 'الملف غير موجود' });
        }

        // احصل على معلومات الملف قبل حذفه
        const stats = await fs.stat(filePath);
        const isDirectory = stats.isDirectory();
        const fileSize = isDirectory ? await calculateDirectorySize(filePath) : stats.size;
        
        await fs.remove(filePath);
        
        // إرسال إشعار عبر الويبهوك عن حذف الملف
        await sendWebhookNotification(userId, serverName, 'حذف ملف', {
            'اسم الملف': fileName,
            'النوع': isDirectory ? 'مجلد' : 'ملف',
            'الحجم': fileSize ? (fileSize / 1024).toFixed(2) + ' KB' : 'غير معروف',
            'وقت الحذف': new Date().toLocaleString('ar-SA'),
            'بواسطة': req.user.username || 'مستخدم غير معروف'
        }).catch(err => console.error('Webhook notification error:', err));
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.json({ success: false, error: error.message });
    }
});

app.get('/download-file/:serverName/:fileName(*)', checkServerAccess, async (req, res) => {
    try {
        const { serverName, fileName } = req.params;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, fileName);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).json({ success: false, error: 'الملف غير موجود' });
        }

        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            return res.status(400).json({ success: false, error: 'لا يمكن تنزيل المجلدات' });
        }

        res.download(filePath);
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// السيرفر يتم تشغيله من خلال http بدلاً من app.listen مباشرة
// http تم إنشاؤه مسبقاً في بداية الملف

app.get('/api/file-content/:serverName/:fileName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول إلى الملفات' });
    }
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        console.log('Attempting to read file:', filePath);

        if (!await fs.pathExists(filePath)) {
            console.log('File not found:', filePath);
            return res.json({ success: false, error: 'الملف غير موجود' });
        }

        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            console.log('Requested path is a directory, not a file');
            return res.status(400).json({ success: false, error: 'لا يمكن تحميل المجلدات' });
        }

        try {
            // محاولة قراءة الملف باستخدام fs.promises
            const content = await fs.promises.readFile(filePath, 'utf8').catch(err => {
                console.error('Error with promises readFile:', err);
                return null;
            });

            if (content !== null) {
                console.log('File read successfully with promises, content length:', content.length);
                return res.json({ success: true, content });
            }

            // إذا فشلت الطريقة الأولى، جرب الطريقة التقليدية
            fs.readFile(filePath, { encoding: 'utf8' }, (err, data) => {
                if (err) {
                    console.error('Error with callback readFile:', err);

                    // محاولة أخيرة بقراءة الملف كبيانات ثنائية ثم تحويلها لنص
                    fs.readFile(filePath, (binaryErr, binaryData) => {
                        if (binaryErr) {
                            console.error('Error with binary readFile:', binaryErr);
                            return res.status(500).json({ success: false, error: 'فشل في قراءة الملف بعد عدة محاولات' });
                        }
                        try {
                            const binaryContent = binaryData.toString('utf8');
                            console.log('File read as binary and converted to string, length:', binaryContent.length);
                            return res.json({ success: true, content: binaryContent });
                        } catch (convErr) {
                            console.error('Error converting binary to string:', convErr);
                            return res.status(500).json({ success: false, error: 'فشل في تحويل محتوى الملف' });
                        }
                    });
                } else {
                    console.log('File read successfully with callback, content length:', data.length);
                    return res.json({ success: true, content: data });
                }
            });
        } catch (readError) {
            console.error('General error reading file content:', readError);
            return res.status(500).json({ success: false, error: `فشل في قراءة الملف: ${readError.message}` });
        }
    } catch (error) {
        console.error('File read error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// صفحة عرض الملف
app.get('/view-file/:serverName/:fileName', checkServerAccess, async (req, res) => {
    try {
        const { serverName, fileName } = req.params;
        const { path: reqPath = '' } = req.query;
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const filePath = path.join(__dirname, 'uploads', userId, serverName, reqPath, fileName);

        // التحقق من وجود الملف
        if (!await fs.pathExists(filePath)) {
            return res.redirect(`/edit-server/${serverName}?error=الملف غير موجود`);
        }

        // التأكد من أنه ليس مجلدًا
        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            return res.redirect(`/edit-server/${serverName}?path=${encodeURIComponent(reqPath ? reqPath + '/' + fileName : fileName)}`);
        }

        // قراءة محتوى الملف
        const content = await fs.readFile(filePath, 'utf8').catch(() => null);
        const fileExtension = path.extname(fileName).toLowerCase();

        // تحديد نوع الملف
        let fileType = 'text';
        if (['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].includes(fileExtension)) {
            fileType = 'image';
        } else if (['.mp4', '.webm', '.ogg'].includes(fileExtension)) {
            fileType = 'video';
        } else if (['.mp3', '.wav'].includes(fileExtension)) {
            fileType = 'audio';
        }

        res.render('file-viewer', {
            user: req.user,
            serverName,
            fileName,
            filePath: reqPath,
            content,
            fileType,
            fileExtension,
            isOwner: req.isOwner,
            userPermissions: req.userPermissions || { canEdit: false, canDelete: false, canStart: false }
        });
    } catch (error) {
        console.error('Error viewing file:', error);
        res.redirect(`/edit-server/${req.params.serverName}?error=${encodeURIComponent('خطأ في عرض الملف')}`);
    }
});
app.post('/api/rename-file/:serverName', checkServerAccess, async (req, res) => {
    if (req.userPermissions && !req.userPermissions.canEdit) {
        return res.status(403).json({ success: false, error: 'ليس لديك صلاحية لتعديل الملفات' });
    }
    try {
        const { serverName } = req.params;
        const { oldPath, newPath } = req.body;
        const userId = req.isOwner ? req.user.id : req.ownerId;

        // التحقق من المسارات
        if (!oldPath || !newPath) {
            return res.json({ success: false, error: 'المسارات غير صحيحة' });
        }

        const oldFullPath = path.join(__dirname, 'uploads', userId, serverName, oldPath);
        const newFullPath = path.join(__dirname, 'uploads', userId, serverName, newPath);

        // التحقق من وجود الملف القديم
        if (!await fs.pathExists(oldFullPath)) {
            return res.json({ success: false, error: 'الملف الأصلي غير موجود' });
        }

        // التحقق من عدم وجود الملف الجديد مسبقاً
        if (await fs.pathExists(newFullPath) && oldFullPath !== newFullPath) {
            return res.json({ success: false, error: 'يوجد ملف بنفس الاسم الجديد' });
        }

        // إعادة تسمية الملف
        await fs.rename(oldFullPath, newFullPath);
        res.json({ success: true });
    } catch (error) {
        console.error('Error renaming file:', error);
        res.json({ success: false, error: error.message });
    }
});
// API للحصول على المستخدمين المشتركين
app.get('/api/allowed-users/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }

    try {
        const { serverName } = req.params;
        const userId = req.user.id;

        // التحقق من ملكية السيرفر
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        if (!await fs.pathExists(serverPath)) {
            return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول' });
        }

        // الحصول على المستخدمين المشتركين
        const botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });

        // إذا لم يكن هناك سجل، قم بإنشاء واحد جديد
        if (!botUser) {
            const newBotUser = new BotUser({
                botName: serverName,
                ownerId: userId,
                allowedUsers: [],
                autoReconnect: false
            });
            await newBotUser.save();
            return res.json({ success: true, users: [] });
        }

        // محاولة إضافة معلومات المستخدم من Discord
        const usersWithInfo = await Promise.all((botUser.allowedUsers || []).map(async (user) => {
            try {
                if (client && client.users) {
                    const discordUser = await client.users.fetch(user.userId).catch(() => null);
                    if (discordUser) {
                        return {
                            ...user.toObject(),
                            username: discordUser.username || `مستخدم ${user.userId}`,
                            avatar: discordUser.displayAvatarURL() || null
                        };
                    }
                }
                return user.toObject();
            } catch (err) {
                console.error(`Error fetching Discord user info for ${user.userId}:`, err);
                return user.toObject();
            }
        }));

        res.json({ success: true, users: usersWithInfo });
    } catch (error) {
        console.error('Error getting allowed users:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// إضافة مستخدم جديد
app.post('/api/add-user/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }

    try {
        const { serverName } = req.params;
        const { userId } = req.body;
        const ownerId = req.user.id;

        if (!userId) {
            return res.json({ success: false, error: 'يجب تحديد معرف المستخدم' });
        }

        // التحقق من ملكية السيرفر
        const serverPath = path.join(__dirname, 'uploads', ownerId, serverName);
        if (!await fs.pathExists(serverPath)) {
            return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول' });
        }

        // التحقق من صحة معرف المستخدم في Discord
        try {
            if (client && client.users) {
                // محاولة العثور على المستخدم في Discord
                await client.users.fetch(userId).catch(() => {
                    throw new Error('معرف المستخدم غير صالح أو غير موجود في Discord');
                });
            }
        } catch (discordError) {
            console.error('Discord user validation error:', discordError);
            return res.json({ success: false, error: 'معرف المستخدم غير صالح' });
        }

        // البحث عن السيرفر في قاعدة البيانات أو إنشاء سجل جديد
        let botUser = await BotUser.findOne({ botName: serverName, ownerId });
        if (!botUser) {
            botUser = new BotUser({
                botName: serverName,
                ownerId,
                allowedUsers: [],
                autoReconnect: false
            });
        }

        // التحقق إذا كان المستخدم موجوداً مسبقاً
        if (botUser.allowedUsers.some(user => user.userId === userId)) {
            return res.json({ success: false, error: 'المستخدم مضاف بالفعل' });
        }

        // إضافة المستخدم بصلاحيات افتراضية
        botUser.allowedUsers.push({
            userId,
            permissions: {
                canEdit: false,
                canDelete: false,
                canStart: false
            }
        });

        await botUser.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding user:', error);
        res.json({ success: false, error: error.message });
    }
});

// إزالة مستخدم
app.post('/api/remove-user/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }

    try {
        const { serverName } = req.params;
        const { userId } = req.body;
        const ownerId = req.user.id;

        // التحقق من ملكية السيرفر
        const serverPath = path.join(__dirname, 'uploads', ownerId, serverName);
        if (!await fs.pathExists(serverPath)) {
            return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول' });
        }

        // البحث عن السيرفر في قاعدة البيانات
        const botUser = await BotUser.findOne({ botName: serverName, ownerId });
        if (!botUser) {
            return res.json({ success: false, error: 'السيرفر غير موجود' });
        }

        // إزالة المستخدم من القائمة
        botUser.allowedUsers = botUser.allowedUsers.filter(user => user.userId !== userId);
        await botUser.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error removing user:', error);
    }
});

// حفظ ملف باستخدام المسار الكامل (الطريقة الجديدة)
app.post('/api/server/:serverName/save-file', checkServerAccess, async (req, res) => {
    try {
        const { serverName } = req.params;
        const { path: filePath, content } = req.body;
        
        if (!filePath) {
            return res.status(400).json({ success: false, error: 'مسار الملف مطلوب' });
        }
        
        const userId = req.isOwner ? req.user.id : req.ownerId;
        const fullPath = path.join(__dirname, 'uploads', userId, serverName, filePath);
        
        // التأكد من وجود المجلد
        const dirPath = path.dirname(fullPath);
        await fs.ensureDir(dirPath);
        
        // حفظ محتوى الملف
        await fs.writeFile(fullPath, content, 'utf8');
        
        return res.json({ success: true });
    } catch (error) {
        console.error('Error saving file:', error);
        res.json({ success: false, error: error.message });
    }
});

// تحديث صلاحيات المستخدم
app.post('/api/update-permission/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }

    try {
        const { serverName } = req.params;
        const { userId, permission, value } = req.body;
        const ownerId = req.user.id;

        if (!userId || !permission || value === undefined) {
            return res.json({ success: false, error: 'معلومات غير كاملة' });
        }

        // التحقق من ملكية السيرفر
        const serverPath = path.join(__dirname, 'uploads', ownerId, serverName);
        if (!await fs.pathExists(serverPath)) {
            return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول' });
        }

        // البحث عن السيرفر في قاعدة البيانات
        const botUser = await BotUser.findOne({ botName: serverName, ownerId });
        if (!botUser) {
            return res.json({ success: false, error: 'السيرفر غير موجود' });
        }

        // تحديث صلاحية المستخدم
        const userIndex = botUser.allowedUsers.findIndex(user => user.userId === userId);
        if (userIndex === -1) {
            return res.json({ success: false, error: 'المستخدم غير موجود' });
        }

        // التحقق من صحة نوع الصلاحية
        const validPermissions = ['canEdit', 'canDelete', 'canStart'];
        if (!validPermissions.includes(permission)) {
            return res.json({ success: false, error: 'نوع الصلاحية غير صالح' });
        }

        // تحديث الصلاحية
        botUser.allowedUsers[userIndex].permissions[permission] = Boolean(value);
        await botUser.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating permission:', error);
        res.json({ success: false, error: error.message });
    }
});
app.post('/api/set-auto-reconnect/:serverName', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'غير مصرح لك' });
    }

    try {
        const { serverName } = req.params;
        const { autoReconnect } = req.body;
        const userId = req.user.id;

        // التحقق من ملكية السيرفر
        const serverPath = path.join(__dirname, 'uploads', userId, serverName);
        if (!await fs.pathExists(serverPath)) {
            return res.status(403).json({ success: false, error: 'ليس لديك صلاحية للوصول' });
        }

        // تحديث أو إنشاء إعدادات البوت
        let botUser = await BotUser.findOne({ botName: serverName, ownerId: userId });
        if (!botUser) {
            botUser = new BotUser({
                botName: serverName,
                ownerId: userId,
                allowedUsers: [],
                autoReconnect: Boolean(autoReconnect)
            });
        } else {
            botUser.autoReconnect = Boolean(autoReconnect);
        }

        await botUser.save();
        console.log(`Auto reconnect for ${serverName} set to: ${autoReconnect}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Auto reconnect error:', error);
        res.json({ success: false, error: error.message });
    }
});