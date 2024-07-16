require('dotenv').config(); // Add this line at the top of your file
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET; // Change this line

app.use(cors({credentials:true,origin:'http://localhost:3000'}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

mongoose.connect(process.env.MONGODB_URI); // Change this line

app.post('/register', async (req,res) => {
  const {username,password} = req.body;
  try{
    const userDoc = await User.create({
      username,
      password:bcrypt.hashSync(password,salt),
    });
    res.json(userDoc);
  } catch(e) {
    console.log(e);
    res.status(400).json(e);
  }
});

app.post('/login', async (req,res) => {
  const {username,password} = req.body;
  const userDoc = await User.findOne({username});
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    // logged in
    jwt.sign({username,id:userDoc._id}, secret, {}, (err,token) => {
      if (err) throw err;
      res.cookie('token', token).json({
        id:userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json('wrong credentials');
  }
});

app.get('/profile', (req,res) => {
  const {token} = req.cookies;
  jwt.verify(token, secret, {}, (err,info) => {
    if (err) throw err;
    res.json(info);
  });
});

app.post('/logout', (req,res) => {
  res.cookie('token', '').json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  try {
    // Ensure a file was uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;

    // Rename the uploaded file with correct extension
    fs.renameSync(path, newPath);

    // Verify JWT token
    const { token } = req.cookies;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { title, summary, content } = req.body;

      // Create new post document
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });

      // Return the created post document
      res.json(postDoc);
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server Error' });
  }
});

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;

  // If a file is uploaded, process the file
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { token } = req.cookies;
  
  // Verify the JWT token
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err;

    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);

    // Check if the post exists
    if (!postDoc) {
      return res.status(404).json('Post not found');
    }

    // Check if the authenticated user is the author
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json('You are not the author');
    }

    // Update post fields
    postDoc.title = title;
    postDoc.summary = summary;
    postDoc.content = content;
    if (newPath) {
      postDoc.cover = newPath;
    }

    // Save the updated post document
    await postDoc.save();

    res.json(postDoc);
  });
});


app.get('/post', async (req,res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({createdAt: -1})
      .limit(20)
  );
});

app.get('/post/:id', async (req, res) => {
  const {id} = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  res.json(postDoc);
})

app.listen(process.env.PORT || 4000); // Change this line