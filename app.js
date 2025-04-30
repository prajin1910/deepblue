const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const cron = require('node-cron');
const port = process.env.PORT || 3000;
const app = express();
const JWT_SECRET = 'your-secret-key'; // Use environment variable in production

// MongoDB Connection
const uri = "mongodb+srv://reksitrajan01:8n4SHiaJfCZRrimg@cluster0.mperr.mongodb.net/test?retryWrites=true&w=majority";
mongoose.connect(uri)
    .then(() => console.log('✅ MongoDB Connected Successfully!'))
    .catch((err) => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
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

// Schema for sensor data
const sensorDataSchema = new mongoose.Schema({
    temperature: Number,
    humidity: Number,
    timestamp: { type: Date, default: Date.now }
});

const DisposedProduct = mongoose.model('DisposedProduct', {
    userId: mongoose.Schema.Types.ObjectId,
    productName: String,
    quantity: Number,
    price: Number, // Added price field for disposed products
    companyName: String,
    location: String,
    email: String,
    expiryDate: Date,
    disposedDate: { type: Date, default: Date.now },
    isExpired: Boolean // To differentiate between expired and expiring products
});

const ProductRequest = mongoose.model('ProductRequest', {
    productId: mongoose.Schema.Types.ObjectId,
    userId: mongoose.Schema.Types.ObjectId, // seller's user ID
    requesterName: String,
    requesterEmail: String,
    requesterPhone: String,
    requestDate: { type: Date, default: Date.now },
    productName: String,
    isExpired: Boolean, // To differentiate between expired and expiring products
    status: { type: String, default: 'pending' } // pending, accepted, rejected
});
// Add this schema near the other schema definitions
const ngoSchema = new mongoose.Schema({
    name: String,
    inchargeName: String,
    email: String,
    contactPhone: String,
    address: String,
    state: String,
    bio: String,
    registeredAt: {
        type: Date,
        default: Date.now
    }
});

// Define schemas
const donationSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    company: String,
    address: String,
    category: String,
    quantity: Number,
    prepDateTime: Date,
    expiryDate: Date,
    specialNote: String,
    pin: String, // Added PIN field
    createdAt: {
      type: Date,
      default: Date.now
    },
    availableQuantity: Number // To track remaining quantity after requests
  });
  
  // Renamed schema from 'Request' to 'NeedRequest'
  const needRequestSchema = new mongoose.Schema({
    donationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Donation'
    },
    requesterName: String,
    requestedQuantity: Number,
    requestSummary: String,
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'completed'],
      default: 'pending'
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    },
    completedDate: {
      type: Date
    }
  });
  
  // Add pre-save middleware to update the updatedAt field
  needRequestSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
  });
  
  const Donation = mongoose.model('Donation', donationSchema);
  // Changed model name from 'Request' to 'NeedRequest'
  const NeedRequest = mongoose.model('NeedRequest', needRequestSchema);
  

// Create the NGO model
const NGO = mongoose.model('NGO', ngoSchema);

// Create models
const Request = mongoose.model('Request', requestSchema);
const SensorData = mongoose.model('SensorData', sensorDataSchema);

// ThingSpeak API configuration
const channelID = '2857456'; // Replace with your ThingSpeak channel ID
const readAPIKey = '3PVRMKZIGG7C7XSF';

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

// Function to fetch data from ThingSpeak and store in MongoDB
async function fetchAndStoreThingSpeakData() {
    try {
        // Fetch the latest data from ThingSpeak
        const response = await axios.get(`https://api.thingspeak.com/channels/${channelID}/feeds.json?api_key=${readAPIKey}&results=1`);
        
        if (response.data && response.data.feeds && response.data.feeds.length > 0) {
            const latestData = response.data.feeds[0];
            
            // Create a new document in MongoDB
            const newData = new SensorData({
                temperature: parseFloat(latestData.field1),
                humidity: parseFloat(latestData.field2),
                timestamp: new Date(latestData.created_at)
            });
            
            // Save to MongoDB
            await newData.save();
            console.log('✅ Data from ThingSpeak saved to MongoDB:', {
                temperature: newData.temperature,
                humidity: newData.humidity,
                timestamp: newData.timestamp
            });
        }
    } catch (error) {
        console.error('❌ Error fetching or storing data from ThingSpeak:', error.message);
    }
}

// Schedule the data fetch every minute
cron.schedule('* * * * *', () => {
    console.log('🔄 Running scheduled data fetch from ThingSpeak');
    fetchAndStoreThingSpeakData();
});

// Routes for donation system
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


app.post('/api/donations', async (req, res) => {
    try {
      // Check if this email already has a pin
      const existingDonation = await Donation.findOne({ email: req.body.myemail });
      let pin = req.body.pin;
      
      // If email exists, use the existing pin instead of creating a new one
      if (existingDonation && existingDonation.pin) {
        pin = existingDonation.pin;
      }
      
      const donation = new Donation({
        name: req.body.myname1,
        email: req.body.myemail,
        phone: req.body.myphone,
        company: req.body.mycompany,
        address: req.body.myadd,
        category: req.body.category,
        quantity: req.body.quantity,
        prepDateTime: req.body.foodprepdatetime,
        expiryDate: req.body.expiry,
        specialNote: req.body.specialnote,
        pin: pin, // Store the PIN with the donation
        availableQuantity: req.body.quantity // Initially, available quantity equals total quantity
      });
  
      await donation.save();
      res.status(201).json({ success: true, message: 'Donation submitted successfully!' });
    } catch (error) {
      console.error('Error saving donation:', error);
      res.status(500).json({ success: false, message: 'Error submitting donation' });
    }
  });
  
  // Check if user exists with specific email
  app.get('/api/check-user', async (req, res) => {
    try {
      const { email } = req.query;
      if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
      }
      
      const existingDonation = await Donation.findOne({ email });
      if (existingDonation) {
        return res.json({ 
          success: true, 
          userExists: true,
          hasPin: !!existingDonation.pin
        });
      }
      
      return res.json({ success: true, userExists: false });
    } catch (error) {
      console.error('Error checking user:', error);
      res.status(500).json({ success: false, message: 'Error checking user' });
    }
  });
  
  // Verify PIN for dashboard access
  app.post('/api/verify-pin', async (req, res) => {
    try {
      const { email, pin } = req.body;
      if (!email || !pin) {
        return res.status(400).json({ success: false, message: 'Email and PIN are required' });
      }
      
      const donation = await Donation.findOne({ email, pin });
      if (!donation) {
        return res.status(401).json({ success: false, message: 'Invalid email or PIN' });
      }
      
      res.json({ success: true, message: 'PIN verified successfully' });
    } catch (error) {
      console.error('Error verifying PIN:', error);
      res.status(500).json({ success: false, message: 'Error verifying PIN' });
    }
  });
  
  app.get('/donations', async (req, res) => {
    try {
      const donations = await Donation.find({ availableQuantity: { $gt: 0 } }).sort({ createdAt: -1 });
      res.render('donations', { donations });
    } catch (error) {
      console.error('Error fetching donations:', error);
      res.status(500).send('Error fetching available donations');
    }
  });
  
  // Update the POST /api/requests endpoint
app.post('/api/requests', async (req, res) => {
    try {
      const { donationId, requesterName, requestedQuantity, requestSummary } = req.body;
      
      // Validate the requested quantity
      const donation = await Donation.findById(donationId);
      if (!donation) {
        return res.status(404).json({ success: false, message: 'Donation not found' });
      }
      
      if (requestedQuantity > donation.availableQuantity) {
        return res.status(400).json({ 
          success: false, 
          message: 'Requested quantity exceeds available amount' 
        });
      }
      
      // Create the request - multiple requests allowed for same donation
      const needRequest = new NeedRequest({
        donationId,
        requesterName,
        requestedQuantity: Number(requestedQuantity),
        requestSummary,
        status: 'pending'
      });
      
      await needRequest.save();
      res.status(201).json({ success: true, message: 'Request sent to donor successfully!' });
    } catch (error) {
      console.error('Error creating request:', error);
      res.status(500).json({ success: false, message: 'Error submitting request' });
    }
  });
  
  // Modify the dashboard API to use NeedRequest instead of Request
  app.get('/api/donor/dashboard', async (req, res) => {
    try {
      const { email } = req.query;
      if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
      }
      
      // Get all donations by this donor
      const donations = await Donation.find({ email }).sort({ createdAt: -1 });
      
      // Get all pending requests for these donations
      const donationIds = donations.map(donation => donation._id);
      const pendingRequests = await NeedRequest.find({ 
        donationId: { $in: donationIds },
        status: 'pending'
      }).populate('donationId');
      
      // Get all approved/allocated requests for these donations (exclude completed ones)
      const allocatedRequests = await NeedRequest.find({ 
        donationId: { $in: donationIds },
        status: 'approved'
      }).sort({ updatedAt: -1 });
      
      // Get completed requests separately
      const completedRequests = await NeedRequest.find({ 
        donationId: { $in: donationIds },
        status: 'completed'
      }).sort({ updatedAt: -1 });
      
      // Enrich the allocated requests with donation details
      const allocatedDonations = [];
      for (const request of [...allocatedRequests, ...completedRequests]) {
        const donation = await Donation.findById(request.donationId);
        if (donation) {
          allocatedDonations.push({
            _id: request._id,
            requesterName: request.requesterName,
            requestedQuantity: request.requestedQuantity,
            requestSummary: request.requestSummary,
            approvedDate: request.updatedAt || request.createdAt,
            completedDate: request.completedDate,
            status: request.status, // Include status to differentiate completed vs approved
            donationDetails: {
              _id: donation._id,
              name: donation.name,
              category: donation.category,
              company: donation.company,
              prepDateTime: donation.prepDateTime,
              expiryDate: donation.expiryDate
            }
          });
        }
      }
      
      res.json({ 
        success: true, 
        donations,
        requests: pendingRequests,
        allocatedDonations: [...allocatedDonations] // Send all allocated donations
    });
    } catch (error) {
      console.error('Error fetching donor dashboard:', error);
      res.status(500).json({ success: false, message: 'Error fetching donor information' });
    }
  });
  
  // Update the PUT /api/requests/:requestId endpoint
app.put('/api/requests/:requestId', async (req, res) => {
    try {
      const { requestId } = req.params;
      const { status } = req.body;
      
      if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status' });
      }
      
      const request = await NeedRequest.findById(requestId);
      if (!request) {
        return res.status(404).json({ success: false, message: 'Request not found' });
      }
      
      // Only update if the status is changing from its current value
      if (request.status !== status) {
        if (status === 'approved') {
          // Update the donation's available quantity
          const donation = await Donation.findById(request.donationId);
          if (!donation) {
            return res.status(404).json({ success: false, message: 'Donation not found' });
          }
          
          if (request.requestedQuantity > donation.availableQuantity) {
            return res.status(400).json({ 
              success: false, 
              message: 'Cannot approve: requested quantity exceeds available amount' 
            });
          }
          
          // Reduce the available quantity
          donation.availableQuantity -= request.requestedQuantity;
          await donation.save();
          
          // Check other pending requests for this donation
          const pendingRequests = await NeedRequest.find({
            donationId: request.donationId,
            status: 'pending',
            _id: { $ne: request._id } // Exclude current request
          });
          
          // Reject requests that now exceed available quantity
          for (const pendingRequest of pendingRequests) {
            if (pendingRequest.requestedQuantity > donation.availableQuantity) {
              pendingRequest.status = 'rejected';
              await pendingRequest.save();
            }
          }
        } 
        else if (status === 'rejected') {
          // If a previously approved request is being rejected, return the quantity to available
          if (request.status === 'approved') {
            const donation = await Donation.findById(request.donationId);
            if (donation) {
              donation.availableQuantity += request.requestedQuantity;
              await donation.save();
            }
          }
        }
        
        // Update request status
        request.status = status;
        await request.save();
      }
      
      res.json({ 
        success: true, 
        message: `Request ${status === 'approved' ? 'approved' : 'rejected'} successfully` 
      });
    } catch (error) {
      console.error('Error updating request status:', error);
      res.status(500).json({ success: false, message: 'Error processing request' });
    }
  });
  
  // Add a new endpoint to mark an allocation as donated/completed
  app.post('/api/allocations/:requestId/complete', async (req, res) => {
    try {
      const { requestId } = req.params;
      
      // Find the request using NeedRequest model
      const request = await NeedRequest.findById(requestId);
      if (!request) {
        return res.status(404).json({ success: false, message: 'Request allocation not found' });
      }
      
      // Verify it's an approved request
      if (request.status !== 'approved') {
        return res.status(400).json({ 
          success: false, 
          message: 'Only approved requests can be marked as donated' 
        });
      }
      
      // Add a completed status field to the request
      request.status = 'completed';
      request.completedDate = new Date();
      await request.save();
      
      res.json({ 
        success: true, 
        message: 'Donation marked as completed successfully' 
      });
    } catch (error) {
      console.error('Error marking donation as completed:', error);
      res.status(500).json({ success: false, message: 'Error processing request' });
    }
  });
  
  app.delete('/api/donations/:donationId', async (req, res) => {
    try {
      const { donationId } = req.params;
      
      const donation = await Donation.findById(donationId);
      if (!donation) {
        return res.status(404).json({ success: false, message: 'Donation not found' });
      }
      
      // Check if there are any approved requests
      const approvedRequests = await NeedRequest.find({
        donationId: donationId,
        status: 'approved'
      });
      
      if (approvedRequests.length > 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'Cannot delete: This donation has approved requests. Please contact support.' 
        });
      }
      
      // Delete all associated requests
      await NeedRequest.deleteMany({ donationId });
      
      // Delete the donation
      await Donation.findByIdAndDelete(donationId);
      
      res.json({ success: true, message: 'Donation deleted successfully' });
    } catch (error) {
      console.error('Error deleting donation:', error);
      res.status(500).json({ success: false, message: 'Error deleting donation' });
    }
  });
  
  // Update donation endpoint
  app.put('/api/donations/:donationId', async (req, res) => {
    try {
      const { donationId } = req.params;
      
      const donation = await Donation.findById(donationId);
      if (!donation) {
        return res.status(404).json({ success: false, message: 'Donation not found' });
      }
      
      // Find the amount of food already allocated through approved requests
      const approvedRequests = await NeedRequest.find({ 
        donationId: donationId, 
        status: 'approved' 
      });
      
      const allocatedQuantity = approvedRequests.reduce((total, request) => {
        return total + request.requestedQuantity;
      }, 0);
      
      // Update basic fields
      const updatableFields = [
        'name', 'phone', 'company', 'address', 'category', 
        'prepDateTime', 'expiryDate', 'specialNote'
      ];
      
      updatableFields.forEach(field => {
        if (req.body[field] !== undefined) {
          donation[field] = req.body[field];
        }
      });
      
      // Update quantity with special handling
      if (req.body.quantity !== undefined) {
        const newQuantity = parseFloat(req.body.quantity);
        
        // Ensure new quantity is not less than what's already been allocated
        if (newQuantity < allocatedQuantity) {
          return res.status(400).json({ 
            success: false, 
            message: `Cannot reduce quantity below ${allocatedQuantity}kg which is already allocated to approved requests`
          });
        }
        
        // Set the new total quantity
        donation.quantity = newQuantity;
        
        // Set the new available quantity (total minus allocated)
        donation.availableQuantity = newQuantity - allocatedQuantity;
      }
      
      await donation.save();
      
      res.json({ 
        success: true, 
        message: 'Donation updated successfully', 
        donation 
      });
    } catch (error) {
      console.error('Error updating donation:', error);
      res.status(500).json({ success: false, message: 'Error updating donation' });
    }
  });

// Update the main route to include only pending and accepted requests
app.get('/main', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const products = await Product.find({ userId: req.user.userId });
        
        const today = new Date();
        const expiringProducts = products.filter(product => {
            const daysToExpiry = Math.ceil((product.expiryDate - today) / (1000 * 60 * 60 * 24));
            return daysToExpiry <= 10 && daysToExpiry > 0;
        });
        
        // Identify expired products
        const expiredProducts = products.filter(product => {
            return product.expiryDate < today;
        });
        
        // Get pending product requests for this user
        const productRequests = await ProductRequest.find({ 
            userId: req.user.userId,
            status: 'pending' // Only show pending requests
        }).sort({ requestDate: -1 });
        
        res.render('main', { 
            products, 
            expiringProducts,
            expiredProducts,
            productRequests,
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

// Add these routes to your existing routes
app.get('/ngo', async (req, res) => {
    try {
        // Fetch all registered NGOs
        const ngos = await NGO.find().sort({ registeredAt: -1 });
        res.render('ngo', { ngos: ngos });
    } catch (error) {
        console.error('Error fetching NGOs:', error);
        res.render('ngo', { ngos: [], error: 'Failed to load NGOs' });
    }
});

app.post('/register-ngo', async (req, res) => {
    try {
        // Validate input
        const { name, inchargeName, email, contactPhone, address, state, bio } = req.body;
        
        if (!name || !inchargeName || !email || !contactPhone || !address || !state) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }
        
        // Check if NGO with the same name or email already exists
        const existingNGO = await NGO.findOne({
            $or: [
                { name: name },
                { email: email }
            ]
        });
        
        if (existingNGO) {
            return res.status(400).json({
                success: false,
                message: 'An NGO with this name or email already exists'
            });
        }
        
        // Create new NGO
        const newNGO = new NGO({
            name,
            inchargeName,
            email,
            contactPhone,
            address,
            state,
            bio
        });
        
        await newNGO.save();
        
        res.status(201).json({
            success: true,
            message: 'NGO registered successfully',
            ngo: newNGO
        });
    } catch (error) {
        console.error('Error registering NGO:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while registering NGO',
            error: error.message
        });
    }
});

// Modified dispose-products route to save disposed products
app.post('/dispose-products', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const quantities = req.body.quantities;
        for (const [productId, quantity] of Object.entries(quantities)) {
            if (!quantity || quantity <= 0) continue;
            
            const product = await Product.findOne({ 
                _id: productId, 
                userId: req.user.userId 
            });
            
            if (product) {
                // Create a new disposed product entry
                const disposedProduct = new DisposedProduct({
                    userId: req.user.userId,
                    productName: product.productName,
                    quantity: parseInt(quantity),
                    price: 0, // Default price, can be updated later
                    companyName: user.companyName,
                    location: product.manufacturer, // Using manufacturer field as location
                    email: user.email,
                    expiryDate: product.expiryDate,
                    isExpired: false // Not expired, just expiring soon
                });
                await disposedProduct.save();
                
                // Update or remove the product from inventory
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


// Modified dispose-product route to handle both expiring and expired products
app.post('/dispose-product', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const product = await Product.findOne({ 
            _id: req.body.productId,
            userId: req.user.userId 
        });
        
        if (!product) {
            return res.status(404).json({ success: false, message: 'Product not found' });
        }

        const disposeQuantity = parseInt(req.body.quantity);
        if (isNaN(disposeQuantity)) {
            return res.status(400).json({ success: false, message: 'Invalid quantity' });
        }

        // Determine if product is expired
        const isExpired = product.expiryDate < new Date();
        
        // Create a new disposed product entry
        const disposedProduct = new DisposedProduct({
            userId: req.user.userId,
            productName: product.productName,
            quantity: disposeQuantity,
            price: 0, // Default price, can be updated later
            companyName: user.companyName,
            location: product.manufacturer,
            email: user.email,
            expiryDate: product.expiryDate,
            isExpired: isExpired
        });
        await disposedProduct.save();
        
        // Update or remove the product from inventory
        if (disposeQuantity >= product.quantity) {
            await Product.deleteOne({ _id: product._id });
        } else {
            product.quantity -= disposeQuantity;
            await product.save();
        }
        
        res.json({ success: true, message: 'Product disposed successfully' });
    } catch (error) {
        console.error('Error disposing product:', error);
        res.status(500).json({ success: false, message: 'Error disposing product' });
    }
});
// Update the expiring and expired routes to filter out products with accepted requests
app.get('/expiring', async (req, res) => {
    try {
        // Get all product IDs from accepted requests
        const acceptedRequests = await ProductRequest.find({ 
            status: 'accepted',
            isExpired: false
        });
        const acceptedProductIds = acceptedRequests.map(req => req.productId);
        
        // Find all non-expired disposed products that haven't been accepted
        const disposedProducts = await DisposedProduct.find({ 
            isExpired: false,
            _id: { $nin: acceptedProductIds } // Exclude products with accepted requests
        }).sort({ disposedDate: -1 });
        
        res.render('expiring', { disposedProducts });
    } catch (error) {
        console.error('Error fetching expiring products:', error);
        res.status(500).send('Error fetching expiring products');
    }
});

app.get('/expired', async (req, res) => {
    try {
        // Get all product IDs from accepted requests
        const acceptedRequests = await ProductRequest.find({ 
            status: 'accepted',
            isExpired: true
        });
        const acceptedProductIds = acceptedRequests.map(req => req.productId);
        
        // Find all expired disposed products that haven't been accepted
        const disposedProducts = await DisposedProduct.find({ 
            isExpired: true,
            _id: { $nin: acceptedProductIds } // Exclude products with accepted requests
        }).sort({ disposedDate: -1 });
        
        res.render('expired', { disposedProducts });
    } catch (error) {
        console.error('Error fetching expired products:', error);
        res.status(500).send('Error fetching expired products');
    }
});

// New route to handle product requests
app.post('/request-product', async (req, res) => {
    try {
        const { productId, requesterName, requesterEmail, requesterPhone, isExpired } = req.body;
        
        const disposedProduct = await DisposedProduct.findById(productId);
        if (!disposedProduct) {
            return res.status(404).json({ success: false, message: 'Product not found' });
        }
        
        const productRequest = new ProductRequest({
            productId: disposedProduct._id,
            userId: disposedProduct.userId,  // seller's user ID
            requesterName,
            requesterEmail,
            requesterPhone,
            productName: disposedProduct.productName,
            isExpired: isExpired === 'true'
        });
        
        await productRequest.save();
        
        res.json({ success: true, message: 'Request submitted successfully!' });
    } catch (error) {
        console.error('Error submitting product request:', error);
        res.status(500).json({ success: false, message: 'Error submitting request' });
    }
});

// Consumer portal route
app.get('/consumer-portal', (req, res) => {
    res.render('consumer-portal');
});
// Donation Routes
app.get('/donate', (req, res) => {
    res.render('donate');
});
app.get('/ngo', (req, res) => {
    res.render('ngo');
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



// Modified dispose-expired-products route to save disposed expired products
app.post('/dispose-expired-products', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const quantities = req.body.quantities;
        for (const [productId, quantity] of Object.entries(quantities)) {
            if (!quantity || quantity <= 0) continue;
            
            const product = await Product.findOne({ 
                _id: productId, 
                userId: req.user.userId 
            });
            
            if (product) {
                // Create a new disposed product entry
                const disposedProduct = new DisposedProduct({
                    userId: req.user.userId,
                    productName: product.productName,
                    quantity: parseInt(quantity),
                    price: 0, // Default price, can be updated later
                    companyName: user.companyName,
                    location: product.manufacturer, // Using manufacturer field as location
                    email: user.email,
                    expiryDate: product.expiryDate,
                    isExpired: true // This is an expired product
                });
                await disposedProduct.save();
                
                // Update or remove the product from inventory
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
        console.error('Error disposing expired products:', error);
        res.redirect('/main');
    }
});


// Request Routes
app.get('/donaters', (req, res) => {
    res.render('request-food');
});

app.get('/reqfood', (req, res) => {
    res.render('reqfood');
});
app.get('/ngo', (req, res) => {
    res.render('ngo');
});
app.get('/info', (req, res) => {
    res.render('info');
});

app.post('/requests', async (req, res) => {
    try {
        const request = new Request({
            orgName: req.body.orgName,
            address: req.body.address,
            contactDetails: req.body.contactDetails,
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

// Sensor data routes
app.get('/sensors', async (req, res) => {
    try {
        // Get the latest 20 records from MongoDB, sorted by timestamp (newest first)
        const data = await SensorData.find().sort({ timestamp: -1 }).limit(20);
        res.render('sensors', { sensorData: data });
    } catch (error) {
        console.error('❌ Error retrieving sensor data:', error.message);
        res.status(500).send('Server Error');
    }
});

// Route to get all sensor data as JSON
app.get('/api/sensor-data', async (req, res) => {
    try {
        // Check if we're receiving data from ESP32
        if (req.query.temperature && req.query.humidity) {
            // Create a new document in MongoDB
            const newData = new SensorData({
                temperature: parseFloat(req.query.temperature),
                humidity: parseFloat(req.query.humidity)
            });
            
            // Save to MongoDB
            await newData.save();
            console.log('✅ Data received directly from ESP32 saved to MongoDB:', {
                temperature: newData.temperature,
                humidity: newData.humidity,
                timestamp: newData.timestamp
            });
            
            return res.json({ success: true, message: 'Data saved successfully' });
        }
        
        // Otherwise, just return the data
        const data = await SensorData.find().sort({ timestamp: -1 }).limit(100);
        res.json(data);
    } catch (error) {
        console.error('❌ Error processing API request:', error.message);
        res.status(500).json({ error: 'Server Error' });
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
// Route to handle accept request
// Route to handle accept request
app.post('/accept-request', authenticateToken, async (req, res) => {
    try {
        const requestId = req.body.requestId;
        
        // Find the request
        const request = await ProductRequest.findById(requestId);
        if (!request || request.userId.toString() !== req.user.userId) {
            return res.status(404).json({ 
                success: false, 
                message: 'Request not found or unauthorized' 
            });
        }
        
        // Find the disposed product
        const disposedProduct = await DisposedProduct.findById(request.productId);
        if (!disposedProduct) {
            return res.status(404).json({ 
                success: false, 
                message: 'Product not found' 
            });
        }
        
        // Update request status to accepted
        request.status = 'accepted';
        await request.save();
        
        // Remove the disposed product
        await DisposedProduct.findByIdAndDelete(request.productId);
        
        res.json({ 
            success: true, 
            message: 'Request accepted successfully',
            requestId: request._id
        });
    } catch (error) {
        console.error('Error accepting request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error accepting request',
            error: error.message 
        });
    }
});

// Route to handle reject request
app.post('/reject-request', authenticateToken, async (req, res) => {
    try {
        const requestId = req.body.requestId;
        
        // Find the request
        const request = await ProductRequest.findById(requestId);
        if (!request || request.userId.toString() !== req.user.userId) {
            return res.status(404).json({ 
                success: false, 
                message: 'Request not found or unauthorized' 
            });
        }
        
        // Update request status to rejected
        request.status = 'rejected';
        await request.save();
        
        res.json({ 
            success: true, 
            message: 'Request rejected successfully',
            requestId: request._id
        });
    } catch (error) {
        console.error('Error rejecting request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error rejecting request',
            error: error.message 
        });
    }
});
// Start server
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
    
    // Fetch sensor data immediately when the server starts
    fetchAndStoreThingSpeakData();
});
