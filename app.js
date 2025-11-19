require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);
// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));


// Passport
app.use(passport.initialize());
app.use(passport.session());


// PostgreSQL Connection
const pool = new Pool({
    connectionString: process.env.DB_CONNECTION_STRING,
    ssl: { rejectUnauthorized: false }
});


const Razorpay = require('razorpay');
const crypto = require('crypto');


// Razorpay client (use env vars)
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || '',
    key_secret: process.env.RAZORPAY_KEY_SECRET || ''
});


pool.connect()
    .then(() => console.log('✅ Connected to PostgreSQL database'))
    .catch(err => console.error('❌ Database connection error:', err));


// Passport Configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:'https://collegepreferencer.com/auth/google/callback'
    // callbackURL:'https://prefrencer.onrender.com/auth/google/callback'
    // http://localhost:3000/auth/google/callback
    // callbackURL:'https://collegepreferencer.com/auth/google/callback' 
    
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const { rows: existingUser } = await pool.query(
            'SELECT * FROM users WHERE google_id = $1 OR email = $2',
            [profile.id, profile.emails[0].value]
        );
       
        if (existingUser.length > 0) {
            if (!existingUser[0].google_id) {
                await pool.query(
                    'UPDATE users SET google_id = $1 WHERE email = $2',
                    [profile.id, profile.emails[0].value]
                );
            }
            return done(null, existingUser[0]);
        } else {
            const { rows } = await pool.query(
                'INSERT INTO users (google_id, name, email, mobile) VALUES ($1, $2, $3, $4) RETURNING *',
                [profile.id, profile.displayName, profile.emails[0].value, null]
            );
            return done(null, rows[0]);
        }
    } catch (err) {
        return done(err, null);
    }
}));


// Serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, rows[0]);
    } catch (err) {
        done(err, null);
    }
});


// Middleware
function ensureAuthenticated(req, res, next) {
    req.isAuthenticated() ? next() : res.redirect('/login');
}


// API: return current user's paid turns (authoritative)
app.get('/user/paid-turns', ensureAuthenticated, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT paid_turns FROM users WHERE id = $1', [req.user.id]);
        const paid_turns = (rows[0] && typeof rows[0].paid_turns !== 'undefined') ? Number(rows[0].paid_turns) : 0;
        res.json({ paid_turns });
    } catch (err) {
        console.error('Error fetching paid turns:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    req.user.mobile ? res.redirect('/') : res.redirect('/complete-profile');
});
app.get('/logout', (req, res) => req.logout(() => res.redirect('/login')));
app.get('/login', (req, res) => req.isAuthenticated() ? res.redirect('/') : res.render('login'));
app.get('/complete-profile', ensureAuthenticated, (req, res) => {
    req.user.mobile ? res.redirect('/') : res.render('complete-profile', { user: req.user });
});


app.get('/terms-and-conditions', (req, res) => {
    res.render('terms-and-conditions', {
        user: req.user || null
    });
});


app.post('/complete-profile', ensureAuthenticated, async (req, res) => {
    try {
        await pool.query('UPDATE users SET mobile = $1 WHERE id = $2', [req.body.mobile, req.user.id]);
        req.user.mobile = req.body.mobile;
        res.redirect('/');
    } catch (err) {
        console.error('Profile update error:', err);
        res.redirect('/complete-profile');
    }
});


// Helper Function (Unchanged)
function generateCategories(selectedCaste, selectedClass, selectedGender) {
    const categories = [];
    const specialCastes = ['EWS', 'JKM', 'JKR', 'NTPC'];
   
    if (specialCastes.includes(selectedCaste)) {
        categories.push(selectedCaste, 'UR/X/OP');
        return categories;
    }
   
    if (selectedCaste === 'FW') {
        categories.push('FW/OP', 'UR/X/OP');
        return categories;
    }
   
    const castes = selectedCaste !== 'UR' ? [selectedCaste, 'UR'] : ['UR'];
    const classes = selectedClass !== 'X' ? [selectedClass, 'X'] : ['X'];
    const genders = selectedGender !== 'OP' ? [selectedGender, 'OP'] : ['OP'];
   
    castes.forEach(caste => classes.forEach(classType => genders.forEach(gender => {
        categories.push(`${caste}/${classType}/${gender}`);
    })));
   
    return categories;
}


// Main Route (Public for SEO crawling and indexing)
app.get('/', async (req, res) => {
    try {
        const [
            instituteTypes,
            cities,
            collegeNames,
            years,
            branches
        ] = await Promise.all([
            pool.query('SELECT DISTINCT institute_type FROM data_table'),
            pool.query('SELECT DISTINCT city FROM data_table WHERE year = 2025'),
            pool.query('SELECT DISTINCT college_name FROM data_table WHERE year = 2025 ORDER BY college_name ASC'),
            pool.query('SELECT DISTINCT year FROM data_table'),
            pool.query('SELECT DISTINCT branch FROM data_table WHERE year = 2025')
        ]);


        // KEY FIX: Maintain object structure for branches
        res.render('index', {
            collegeNames: collegeNames.rows.map(row => row.college_name),
            instituteTypes: instituteTypes.rows.map(row => row.institute_type),
            cities: cities.rows.map(row => row.city).sort(),
            years: years.rows.map(row => row.year),
            castes: ['EWS', 'FW', 'OBC', 'SC', 'ST', 'UR'],
            classes: ['X', 'H', 'S', 'NCC', 'FF'],
            genders: ['OP', 'F'],
            branches: branches.rows, // Pass as array of objects
            user: req.user || null
        });
    } catch (err) {
        console.error('Main page error:', err);
        res.status(500).send('Internal Server Error');
    }
});




 function ensureArray(val) {
    if (Array.isArray(val)) return val;
    if (val === undefined || val === null) return [];
    return [val];
}


// AJAX Routes (Maintain object structure for consistency)
app.post('/update-cities', async (req, res) => {
    try {
        const instituteTypes = ensureArray(req.body.institute_types);
        const { rows } = await pool.query(
            'SELECT DISTINCT city FROM data_table WHERE institute_type = ANY($1) AND year = 2025',
            [instituteTypes]
        );
        res.json({ cities: rows.map(row => row.city).sort() });
    } catch (err) {
        console.error('Cities update error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/update-colleges', async (req, res) => {
    try {
        const instituteTypes = ensureArray(req.body.institute_types);
        const cities = ensureArray(req.body.cities);
        const { rows } = await pool.query(
            `SELECT DISTINCT college_name FROM data_table
             WHERE institute_type = ANY($1)
             AND city = ANY($2)
             AND year = 2025
             ORDER BY college_name ASC`,
            [instituteTypes, cities]
        );
        res.json({ colleges: rows.map(row => row.college_name) });
    } catch (err) {
        console.error('Colleges update error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/update-branches', async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT DISTINCT branch FROM data_table WHERE college_name = ANY($1) AND year = 2025',
            [req.body.colleges || []]
        );
        // Return array of branch names (strings)
        res.json({ branches: rows.map(row => row.branch) });
    } catch (err) {
        console.error('Branches update error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/generate-categories', (req, res) => {
    res.json({ categories: generateCategories(req.query.caste, req.query.class, req.query.gender) });
});


// Search Route (Unchanged from your original logic)
app.post('/search', ensureAuthenticated, async (req, res) => {
    try {
        const rank = parseInt(req.body.rank);
        const selectedCaste = req.body.caste;
        const selectedClass = req.body.class;
        const selectedGender = req.body.gender;
      //  const selectedCollegeNames = req.body.college_name || [];
        //const instituteTypes = req.body.institute_type || [];
        //const selectedCities = req.body.city || [];
        const selectedRound = req.body.round;
        const rankRange = parseInt(req.body.rank_range);
        const domicile = req.body.domicile;
        const sortBy = req.body.sort_by || 'closing_rank';
        //const selectedBranches = req.body.branch || [];










const selectedCollegeNames = ensureArray(req.body.college_name);
const instituteTypes = ensureArray(req.body.institute_type);
const selectedCities = ensureArray(req.body.city);
const selectedBranches = ensureArray(req.body.branch);
// const selectedCategories = ensureArray(req.body.selectedCategories);


        const lowerBound = rank - rankRange;
        const upperBound = rank + rankRange;


        // Generate categories
      let selectedCategories = req.body.selectedCategories || [];
      if (!Array.isArray(selectedCategories)) {
        selectedCategories = [selectedCategories];
     }
let categories = selectedCategories.length > 0 ?
    selectedCategories :
    generateCategories(selectedCaste, selectedClass, selectedGender);


if (!Array.isArray(categories)) {
    categories = [categories];
}
        // Create condition for selected categories
        const categoryCondition = categories.length > 0 ?
            `allotted_category = ANY($8)` :
            'TRUE';


        // Handle round values
        const roundValues = selectedRound === 'FIRST&UPGRADE' ?
            ['FIRST', 'UPGRADE'] :
            [selectedRound];


        // Domicile condition
        let domicileCondition = '';
        if (domicile === 'AI') {
            domicileCondition = 'AND (domicile = \'AI\' OR domicile = \'PR\' OR domicile = \'NO\')';
        } else if (domicile === 'Y') {
            domicileCondition = 'AND (domicile = \'YE\' OR domicile = \'PR\')';
        }


        // Main query
        const query = `
            SELECT college_name, institute_type, branch, allotted_category,
                   opening_rank, closing_rank, city, year, round
            FROM data_table
            WHERE closing_rank BETWEEN $1 AND $2
            AND (${categoryCondition})
            AND college_name = ANY($3)
            AND institute_type = ANY($4)
            AND branch = ANY($5)
            AND city = ANY($6)
            AND year = 2025
            AND round = ANY($7)
            ${domicileCondition}
        `;


        const values = [
            lowerBound,
            upperBound,
            selectedCollegeNames,
            instituteTypes,
            selectedBranches,
            selectedCities,
            roundValues,
            categories
        ];


    const { rows: results } = await pool.query(query, values);
       
        // Process results (same as your original code)
        const uniqueResults = {};
        results.forEach(row => {
            const key = `${row.college_name}-${row.branch}`;
            if (!uniqueResults[key] || row.closing_rank > uniqueResults[key].closing_rank) {
                // Add the 2025 ranks with the correct year suffix
                row.opening_rank_2025 = row.opening_rank;
                row.closing_rank_2025 = row.closing_rank;
                uniqueResults[key] = row;
            }
        });


        const finalResults = Object.values(uniqueResults);


        // Handle paid turns: do not decrement if there are zero results
        // Store turns BEFORE any decrement
// Store paid turns BEFORE any decrement
let turnsBeforeSearch = req.user.paid_turns;
let paidSearchConsumed = false;


if (finalResults.length > 0) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const { rows: userRows } = await client.query('SELECT paid_turns FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
        let paidTurns = (userRows[0] && userRows[0].paid_turns) || 0;
        // Store turnsBeforeSearch BEFORE any decrement
        turnsBeforeSearch = paidTurns;
        if (paidTurns > 0) {
            // decrement atomically
            await client.query('UPDATE users SET paid_turns = GREATEST(paid_turns - 1, 0) WHERE id = $1', [req.user.id]);
            paidTurns = paidTurns - 1;
            paidSearchConsumed = true;
            // reflect in req.user for rendering
            req.user.paid_turns = paidTurns;
        }
        await client.query('COMMIT');
    } catch (txnErr) {
        await client.query('ROLLBACK');
        console.error('Paid-turns transaction error:', txnErr);
    } finally {
        client.release();
    }
}


// Store the actual turns BEFORE search (crucial for display logic)
req.session.searchPayload = {
    results: finalResults,
    search: { rank, selectedCaste, domicile, rankRange, sortBy },
    paidSearchConsumed,
    turnsBeforeSearch
};




        // Historical data processing
        const historicalQuery = `
            SELECT college_name, branch, allotted_category, round, year, opening_rank, closing_rank
            FROM data_table
            WHERE year IN (2022, 2023, 2024)
            AND round = ANY($1)
        `;
        const historicalResult = await pool.query(historicalQuery, [roundValues]);
        const historicalData = {};
        historicalResult.rows.forEach(rank => {
            const key = `${rank.college_name}-${rank.branch}-${rank.allotted_category}-${rank.round}-${rank.year}`;
            historicalData[key] = rank;
        });


        // Merge historical data
        finalResults.forEach(result => {
            [2022, 2023, 2024].forEach(year => {
                const key = `${result.college_name}-${result.branch}-${result.allotted_category}-${result.round}-${year}`;
                if (historicalData[key]) {
                    result[`opening_rank_${year}`] = historicalData[key].opening_rank;
                    result[`closing_rank_${year}`] = historicalData[key].closing_rank;
                } else {
                    result[`opening_rank_${year}`] = 'N/A';
                    result[`closing_rank_${year}`] = 'N/A';
                }
            });
        });


        // Trend ranks
        const trendResult = await pool.query('SELECT college_name, branch, rank_number FROM ranked_list');
        const rankMap = new Map();
        trendResult.rows.forEach(row => {
            rankMap.set(`${row.college_name}-${row.branch}`, row.rank_number);
        });


        // Sorting
        finalResults.sort((a, b) => {
            if (sortBy === 'lastYearTrend') {
                const keyA = `${a.college_name}-${a.branch}`;
                const keyB = `${b.college_name}-${b.branch}`;
                const rankA = rankMap.get(keyA) || Number.MAX_SAFE_INTEGER;
                const rankB = rankMap.get(keyB) || Number.MAX_SAFE_INTEGER;
                return rankA - rankB;
            } else if (sortBy === 'closing_rank') {
                return a.closing_rank_2025 - b.closing_rank_2025;
            } else if (sortBy === 'opening_rank') {
                return a.opening_rank_2025 - b.opening_rank_2025;
            }
            return 0;
        });


        // Store the computed results and related metadata in session and redirect (PRG pattern)
        // This prevents the browser from re-submitting the POST on refresh and avoids duplicate turn consumption.
        req.session.searchPayload = {
            results: finalResults,
            search: { rank, selectedCaste, domicile, rankRange, sortBy },
            paidSearchConsumed,
            turnsBeforeSearch
        };
        return res.redirect('/results');
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Results page (GET) - reads search payload from session and renders results without re-running the search
app.get('/results', ensureAuthenticated, async (req, res) => {
    try {
        const payload = req.session && req.session.searchPayload;
        if (!payload) {
            // No search in session; redirect to homepage
            return res.redirect('/');
        }


        // Render results using the stored payload. Do NOT re-run the search logic here — that would re-consume turns.
        return res.render('results', {
            results: payload.results || [],
            user: req.user || null,
            search: payload.search || {},
            paidSearchConsumed: payload.paidSearchConsumed || false,
            turnsBeforeSearch: payload.turnsBeforeSearch || 0
        });
    } catch (err) {
        console.error('Results GET error:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Create Razorpay order
app.post('/payment/create-order', ensureAuthenticated, async (req, res) => {
    try {
        const { plan } = req.body; // 'small' | 'medium' | 'large'
        const plans = {
            small: { amount: 20000, turns: 5, label: '₹200 — 5 turns' },
            medium: { amount: 50000, turns: 15, label: '₹500 — 15 turns' },
            large: { amount: 100000, turns: 50, label: '₹1000 — 50 turns' }
        };
        if (!plans[plan]) return res.status(400).json({ error: 'Invalid plan' });


        const orderOptions = {
            amount: plans[plan].amount, // in paise
            currency: 'INR',
            receipt: `rcpt_${Date.now()}_${req.user.id}`,
            payment_capture: 1
        };


        const order = await razorpay.orders.create(orderOptions);
        // store mapping receipt -> plan turns in payments table
        await pool.query('INSERT INTO payments(receipt_id, user_id, plan_key, amount, order_id, status) VALUES($1,$2,$3,$4,$5,$6)', [order.receipt, req.user.id, plan, order.amount, order.id, 'CREATED']);
        // Persist context for verification: capture origin ('index' | 'results') and turnsBeforeSearch snapshot
        // Prefer explicit origin from client, fallback to Referer header, then final fallback to heuristic.
        try {
            const originFromBody = (req.body && typeof req.body.origin === 'string') ? req.body.origin.toLowerCase() : undefined;
            const referer = req.get('referer') || '';
            let origin = originFromBody || (referer.includes('/results') ? 'results' : 'index');
            // Final fallback to legacy heuristic if still unknown
            if (!origin) {
                const hasSearchPayload = !!(req.session && req.session.searchPayload);
                origin = hasSearchPayload ? 'results' : 'index';
            }
            // Prefer explicit turnsBeforeSearch from body (results page can pass it)
            let tb = undefined;
            if (typeof req.body?.turnsBeforeSearch === 'number' && !Number.isNaN(req.body.turnsBeforeSearch)) {
                tb = Number(req.body.turnsBeforeSearch);
            }
            // If not provided, try session snapshot when origin is results
            if (typeof tb === 'undefined' && origin === 'results' && req.session && req.session.searchPayload && typeof req.session.searchPayload.turnsBeforeSearch !== 'undefined') {
                tb = Number(req.session.searchPayload.turnsBeforeSearch);
            }
            // Fallback to current paid turns
            if (typeof tb === 'undefined') {
                tb = Number(req.user.paid_turns || 0);
            }
            if (!req.session.pendingPayments) req.session.pendingPayments = {};
            req.session.pendingPayments[order.receipt] = { tb, origin };
        } catch (e) {}
        res.json({ order, planKey: plan, planLabel: plans[plan].label, turns: plans[plan].turns, key_id: process.env.RAZORPAY_KEY_ID || '' });
    } catch (err) {
        console.error('Create order error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Verify payment
// Verify payment
// Verify payment
// Verify payment - SIMPLIFIED VERSION
// ...existing code...
app.post('/payment/verify', ensureAuthenticated, async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature, turnsBeforeSearch } = req.body;
       
        // Verify signature
        const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '');
        hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
        const generated_signature = hmac.digest('hex');


        if (generated_signature !== razorpay_signature) {
            return res.status(400).json({ error: 'Invalid signature' });
        }


        // Get payment details
        const { rows } = await pool.query('SELECT * FROM payments WHERE order_id = $1', [razorpay_order_id]);
        if (!rows[0]) return res.status(400).json({ error: 'Order not found' });
        const receiptId = rows[0].receipt_id;
        // Prefer session-captured context associated with the receipt; fallback to client-provided value
        const sessionEntry = (req.session && req.session.pendingPayments && typeof req.session.pendingPayments[receiptId] !== 'undefined')
            ? req.session.pendingPayments[receiptId]
            : undefined;
        // Back-compat: support both numeric (old) and object { tb, origin } (new) entries
        const tbFromSession = (typeof sessionEntry === 'object' && sessionEntry !== null && 'tb' in sessionEntry)
            ? Number(sessionEntry.tb)
            : (typeof sessionEntry === 'number' ? Number(sessionEntry) : (typeof turnsBeforeSearch !== 'undefined' ? Number(turnsBeforeSearch) : undefined));
        const originHint = (typeof sessionEntry === 'object' && sessionEntry !== null && sessionEntry.origin) ? String(sessionEntry.origin) : 'unknown';
        const effectiveTB = (typeof tbFromSession === 'number' && !Number.isNaN(tbFromSession)) ? tbFromSession : 0;
       
        const planKey = rows[0].plan_key;
        const planTurns = planKey === 'small' ? 5 : planKey === 'medium' ? 15 : 50;
        const client = await pool.connect();
        let newTurns = 0;
        let turnsActuallyAdded = 0;
        let lockedAtPurchase = false;
        try {
            await client.query('BEGIN');
            const { rows: userRows } = await client.query(
                'SELECT paid_turns FROM users WHERE id = $1 FOR UPDATE',
                [req.user.id]
            );
            const currentTurns = userRows[0]?.paid_turns || 0;
            // Decide immediate unlock based on the live balance at purchase time, not stale snapshots
            lockedAtPurchase = currentTurns <= 0;
            // Only apply the immediate unlock consumption (-1) for purchases initiated on the results page
            // where the page is currently locked (no available turns). On index page, always add full turns.
            if (originHint === 'results' && lockedAtPurchase) {
                turnsActuallyAdded = Math.max(0, planTurns - 1);
            } else {
                turnsActuallyAdded = planTurns;
            }
            newTurns = currentTurns + turnsActuallyAdded;
            await client.query(
                'UPDATE users SET paid_turns = $1 WHERE id = $2',
                [newTurns, req.user.id]
            );
            await client.query(
                'UPDATE payments SET status = $1, payment_id = $2 WHERE order_id = $3',
                ['PAID', razorpay_payment_id, razorpay_order_id]
            );
            await client.query('COMMIT');
        } catch (txnErr) {
            await client.query('ROLLBACK');
            throw txnErr;
        } finally {
            client.release();
        }
        // reflect new turns in session user and cleanup session pending mapping
        try { req.user.paid_turns = newTurns; } catch(e) {}
    try { if (req.session && req.session.pendingPayments && receiptId) { delete req.session.pendingPayments[receiptId]; } } catch(e) {}
        res.json({
            success: true,
            newTurns: newTurns,
            wasLocked: lockedAtPurchase,
            turnsAdded: turnsActuallyAdded
        });
    } catch (err) {
        console.error('Payment verify error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// ...existing code...


// Start server
app.listen(port, () => {
    console.log(`\n✅ ==============================================`);
    console.log(`✅  Server running at http://localhost:${port}/`);
    console.log(`✅ ==============================================`);
    console.log(`\n🌐 Open in browser: http://localhost:${port}/`);
    console.log(`🚨 Press Ctrl+C to stop the server\n`);
});







