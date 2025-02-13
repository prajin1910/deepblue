
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const port = process.env.PORT || 3000// Correct way
const app = express();
const JWT_SECRET = 'your-secret-key'; // Use environment variable in production

// MongoDB Connection
const uri = "mongodb+srv://reksitrajan01:8n4SHiaJfCZRrimg@cluster0.mperr.mongodb.net/test?retryWrites=true&w=majority";
mongoose.connect(uri)
    .then(() => console.log('MongoDB Connected Successfully!'))
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// Schema definitions
const donationSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    company: String,
    address: String,
    category: String,
    quantity: Number,
    foodPrepDateTime: Date,
    expiry: Date,
    specialNote: String
});

const requestSchema = new mongoose.Schema({
    orgName: String,
    address: String,
    contactDetails: String,
    membersCount: Number,
    description: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', {
    username: String,
    email: String,
    password: String,
    companyName: String
});

const Product = mongoose.model('Product', {
    userId: mongoose.Schema.Types.ObjectId,
    productName: String,
    quantity: Number,
    manufacturer: String,
    expiryDate: Date,
    createdAt: { type: Date, default: Date.now }
});

const Donation = mongoose.model('Donation', donationSchema);
const Request = mongoose.model('Request', requestSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static('views'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        return res.redirect('/');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/');
    }
};

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const existingUser = await User.findOne({ 
            $or: [
                { username: req.body.username },
                { email: req.body.email }
            ]
        });

        if (existingUser) {
            const message = existingUser.username === req.body.username ? 
                'Username already taken' : 'Email already registered';
            return res.render('register', { message });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            companyName: req.body.companyName
        });
        await user.save();
        res.render('register', { message: 'Registered successfully' });
    } catch (error) {
        res.render('register', { message: 'Registration failed' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            const token = jwt.sign(
                { userId: user._id, email: user.email },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            res.cookie('token', token, { 
                httpOnly: true,
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });
            res.redirect('/main');
        } else {
            res.render('register', { message: 'Invalid email or password' });
        }
    } catch (error) {
        res.render('register', { message: 'Login failed' });
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Protected Routes
app.get('/main', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const products = await Product.find({ userId: req.user.userId });
        const expiringProducts = products.filter(product => {
            const daysToExpiry = Math.ceil((product.expiryDate - new Date()) / (1000 * 60 * 60 * 24));
            return daysToExpiry <= 10 && daysToExpiry > 0;
        });
        
        res.render('main', { 
            products, 
            expiringProducts,
            user: {
                username: user.username,
                email: user.email,
                companyName: user.companyName
            }
        });
    } catch (error) {
        console.error('Error loading main page:', error);
        res.redirect('/');
    }
});

app.post('/add-product', authenticateToken, async (req, res) => {
    try {
        const product = new Product({
            userId: req.user.userId,
            productName: req.body.productName,
            quantity: parseInt(req.body.quantity),
            manufacturer: req.body.manufacturer,
            expiryDate: new Date(req.body.expiryDate)
        });
        
        await product.save();
        res.redirect('/main');
    } catch (error) {
        console.error('Error adding product:', error);
        res.redirect('/main');
    }
});

app.post('/manage-product/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findOne({ 
            _id: req.params.id,
            userId: req.user.userId 
        });
        
        if (product) {
            product.expiryDate = new Date(product.expiryDate.getTime() + (30 * 24 * 60 * 60 * 1000));
            await product.save();
        }
        
        res.redirect('/main');
    } catch (error) {
        console.error('Error managing product:', error);
        res.redirect('/main');
    }
});

app.post('/manage-all-products', authenticateToken, async (req, res) => {
    try {
        const products = await Product.find({ userId: req.user.userId });
        for (const product of products) {
            product.expiryDate = new Date(product.expiryDate.getTime() + (30 * 24 * 60 * 60 * 1000));
            await product.save();
        }
        res.redirect('/main');
    } catch (error) {
        console.error('Error managing products:', error);
        res.redirect('/main');
    }
});

app.post('/dispose-products', authenticateToken, async (req, res) => {
    try {
        const quantities = req.body.quantities;
        for (const [productId, quantity] of Object.entries(quantities)) {
            if (!quantity || quantity <= 0) continue;
            
            const product = await Product.findOne({ 
                _id: productId, 
                userId: req.user.userId 
            });
            
            if (product) {
                if (parseInt(quantity) >= product.quantity) {
                    await Product.deleteOne({ _id: product._id });
                } else {
                    product.quantity -= parseInt(quantity);
                    await product.save();
                }
            }
        }
        res.redirect('/main');
    } catch (error) {
        console.error('Error disposing products:', error);
        res.redirect('/main');
    }
});

app.post('/dispose-product', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findOne({ 
            _id: req.body.productId,
            userId: req.user.userId 
        });
        
        if (product) {
            const disposeQuantity = parseInt(req.body.quantity);
            if (disposeQuantity >= product.quantity) {
                await Product.deleteOne({ _id: product._id });
            } else {
                product.quantity -= disposeQuantity;
                await product.save();
            }
        }
        
        res.redirect('/main');
    } catch (error) {
        console.error('Error disposing product:', error);
        res.redirect('/main');
    }
});

// Donation Routes
// Donation Routes
app.get('/donate', (req, res) => {
    res.render('donate');
});

app.post('/donate', async (req, res) => {
    try {
        const donation = new Donation({
            name: req.body.myname1,
            email: req.body.myemail,
            phone: req.body.myphone,
            company: req.body.mycompany,
            address: req.body.myadd,
            category: req.body.category,
            quantity: req.body.quantity,
            foodPrepDateTime: req.body.foodprepdatetime,
            expiry: new Date(req.body.expiry),
            specialNote: req.body.specialnote
        });

        await donation.save();
        res.json({ success: true, message: 'Successfully submitted!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error submitting donation' });
    }
});

app.get('/donations', async (req, res) => {
    try {
        const donations = await Donation.find()
            .sort({ expiry: 1 })
            .exec();
        res.render('donations', { donations });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error fetching donations');
    }
});

// Request Routes
app.get('/donaters', (req, res) => {
    res.render('request-food');
});

app.get('/reqfood', (req, res) => {
    res.render('reqfood');
});

app.post('/requests', async (req, res) => {
    try {
        const request = new Request({
            orgName: req.body.orgName,  // Changed from org_name to orgName
            address: req.body.address,
            contactDetails: req.body.contactDetails,  // Changed from contact_details to contactDetails
            membersCount: parseInt(req.body.membersCount),
            description: req.body.description
        });

        await request.save();
        res.json({ success: true, message: 'Request submitted successfully!' });
    } catch (error) {
        console.error('Request submission error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error submitting request',
            error: error.message
        });
    }
});
app.get('/viewrequests', async (req, res) => {
    try {
        const requests = await Request.find().sort({ createdAt: -1 });
        res.render('viewrequests', { 
            requests,
            formatDate: (date) => {
                return new Date(date).toLocaleDateString();
            }
        });
    } catch (error) {
        console.error('Error fetching requests:', error);
        res.status(500).render('error', { 
            message: 'Error fetching requests', 
            error: error 
        });
    }
});



// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', { 
        message: 'Something broke!', 
        error: err 
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});