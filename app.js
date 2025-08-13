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

pool.connect()
    .then(() => console.log('✅ Connected to PostgreSQL database'))
    .catch(err => console.error('❌ Database connection error:', err));

// Passport Configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:'http://localhost:3000/auth/google/callback' 
    // callbackURL:'https://prefrencer.onrender.com/auth/google/callback' 
        	// http://localhost:3000/auth/google/callback
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

// Main Route (Fixed for template compatibility)
app.get('/', ensureAuthenticated, async (req, res) => {
    try {
        const [
            instituteTypes,
            cities,
            collegeNames,
            years,
            branches
        ] = await Promise.all([
            pool.query('SELECT DISTINCT institute_type FROM data_table'),
            pool.query('SELECT DISTINCT city FROM data_table WHERE year = 2024'),
            pool.query('SELECT DISTINCT college_name FROM data_table WHERE year = 2024 ORDER BY college_name ASC'),
            pool.query('SELECT DISTINCT year FROM data_table'),
            pool.query('SELECT DISTINCT branch FROM data_table WHERE year = 2024')
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
            'SELECT DISTINCT city FROM data_table WHERE institute_type = ANY($1) AND year = 2024',
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
             AND year = 2024
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
            'SELECT DISTINCT branch FROM data_table WHERE college_name = ANY($1) AND year = 2024',
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
            AND year = 2024
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
                uniqueResults[key] = row;
            }
        });

        const finalResults = Object.values(uniqueResults);

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
            const keys = [2022, 2023, 2024].map(year => 
                `${result.college_name}-${result.branch}-${result.allotted_category}-${result.round}-${year}`
            );
            
            keys.forEach((key, i) => {
                const year = 2022 + i;
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
                return a.closing_rank_2024 - b.closing_rank_2024;
            } else if (sortBy === 'opening_rank') {
                return a.opening_rank_2024 - b.opening_rank_2024;
            }
            return 0;
        });

        res.render('results', { results: finalResults });
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Start server
app.listen(port, () => {
    console.log(`\n✅ ==============================================`);
    console.log(`✅  Server running at http://localhost:${port}/`);
    console.log(`✅ ==============================================`);
    console.log(`\n🌐 Open in browser: http://localhost:${port}/`);
    console.log(`🚨 Press Ctrl+C to stop the server\n`);
});