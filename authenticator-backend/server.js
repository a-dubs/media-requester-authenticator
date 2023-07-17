const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// import mongoose model for DB
const User = require('./models/User');

// use CORS to allow cross-origin requests
const cors = require('cors');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://127.0.0.1:27017/media-requester', { useNewUrlParser: true, useUnifiedTopology: true });


const requireAdminAuth = (req, res, next) => {
    if (req.headers.authorization) {
      const auth = req.headers.authorization.split(' ')[1];
      const [username, password] = Buffer.from(auth, 'base64').toString('utf8').split(':');
  
      if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        next();
      } else {
        res.status(403).send('Incorrect admin credentials');
      }
    } else {
      res.status(401).send('Authorization required');
    }
  };


app.get('/users', requireAdminAuth, async (req, res) => {
    // const users = await User.find({});
    const users = []
    res.json(users);
});

app.post('/register', async (req, res) => {

    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPassword = process.env.ADMIN_PASSWORD;

    // get auth header to authenticate admin user 
    const authHeader = req.headers['authorization'];
    const [username, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    // nake sure admin user is authenticated and no one else can register
    if (username !== adminUsername || password !== adminPassword) {
        return res.status(403).send('Access denied');
    }
    // do the registration logic
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: hashedPassword
        });

        const result = await user.save();
        res.send(result);
    } catch {
        res.status(500).send();
    }
}); 

// app.post('/login', async (req, res) => {
//     const user = await User.findOne({ username: req.body.username });
//     if (user == null) {
//         return res.status(400).send('Cannot find user');
//     }

//     try {
//         if (await bcrypt.compare(req.body.password, user.password)) {
//             const accessToken = jwt.sign(user.username, process.env.ACCESS_TOKEN_SECRET);
//             res.json({ accessToken: accessToken });
//         } else {
//             res.send('Not Allowed');
//         }
//     } catch {
        
//         res.status(500).send();
//     }
// });

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
      const user = await User.findOne({ username });
    
        if (!user) {
          console.log('User not found')
        return res.status(401).send('User not found');
      }
    
      const validPassword = await bcrypt.compare(password, user.password);
      console.log(validPassword);
        if (!validPassword) {
          console.log('Invalid username or password')
        return res.status(401).send('Invalid username or password');
      }
        
      const SECRET = process.env.JWT_SECRET;
      
      const token = jwt.sign({ _id: user._id, username: user.username }, SECRET);
        res.status(200).send({ "token":token, "username":user.username });
      
    } catch (err) {
      console.error(err);  // Log the error details to the console
      res.status(500).send('Something went wrong');
    }
  });

// Delete user
app.delete('/users/:id', requireAdminAuth, async (req, res) => {
    try {
        const _id = req.params.id;
        const user = await User.findOneAndDelete({ _id });

        if (!user) {
            return res.status(404).send();
        }

        res.send(user);
    } catch (e) {
        res.status(500).send();
    }
});

// Update user
app.patch('/users/:id', requireAdminAuth, async (req, res) => {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['username', 'password'];
    const isValidOperation = updates.every((update) => allowedUpdates.includes(update));

    if (!isValidOperation) {
        return res.status(400).send({ error: 'Invalid updates!' });
    }

    try {
        const _id = req.params.id;
        const user = await User.findOne({ _id });

        if (!user) {
            return res.status(404).send();
        }

        updates.forEach((update) => user[update] = req.body[update]);
        await user.save();

        res.send(user);
    } catch (e) {
        res.status(400).send(e);
    }
});

app.listen(process.env.PORT || 5000);
