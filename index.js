const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const { ObjectId } = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 3000;

// Body parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());


function convertStringIdToMongoDbId(id) {
  try {
      const mongoDbId = new ObjectId(id);
      return mongoDbId;
  } catch (error) {
      console.log(`Invalid ID ${id}`, error);
      return null;
  }
}

// Connect to MongoDB
mongoose.connect(`${process.env.mongodb_url}:${process.env.mongodb_port}/${process.env.mongodb_dbname}`, { user: process.env.mongodb_username, pass: process.env.mongodb_password, authSource: process.env.mongodb_authsource});

let db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));


// User model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
});

userSchema.pre('save', async function(next) {
  const user = this;
  console.log("Pre-Save hook called with user: ", JSON.stringify(user));
  if (!user.isModified('password')) return next(); // Skip hashing password if it's not modified

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(user.password, salt, 10000, 512, 'sha512').toString('hex');
  user.password = `${hash}::${salt}`;
  next();
});

const User = mongoose.model('User', userSchema);

// Project model
const projectSchema = new mongoose.Schema({
  name: String,
  description: String,
  cores: Number,
  memory: Number,
  disk: Number,
});

const Project = mongoose.model('Project', projectSchema);

// VM model
const vmSchema = new mongoose.Schema({
  image: String,
  name: String,
  description: String,
  privNetworkIP: String,
  serverType: String,
  status: String,
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  cores: Number,
  memory: Number,
  disk: Number,
});

const VM = mongoose.model('VM', vmSchema);




// API endpoint for user registration
app.post('/api/userRegister', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  if (!username || !password) {
    return res.status(400).send({ message: 'Invalid request' });
  }

  try {
    const user = await User.findOne({ username }).exec();

    if (user) {
      return res.status(401).send({ message: 'Username already exists' });
    }

    const newUser = new User({ username, password, email });

    await newUser.save();

    return res.status(201).send({ message: 'User registered successfully' });
  } catch (err) {
    if (err.name === 'MongoServerError' && err.code === 11000) {
      // Duplicate key error: username already exists
      return res.status(409).send({ message: 'Username already exists' });
    } else {
      // Other server errors
      return res.status(500).send({ message: 'Server error' });
    }
  }
});


// API endpoint for user login
app.post('/api/userLogin', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  console.log("Login attempt with username: ", username, " and password: ", password)

  if (!username || !password) {
    return res.status(400).send({ message: 'Invalid request' });
  }

  try {
    const user = await User.findOne({ username }).exec();

    if (!user) {
      return res.status(401).send({ message: 'User not found' });
    }

    const storedPasswordHash = user.password;
    const [hash, salt] = storedPasswordHash.split('::');

    const inputHash = crypto.pbkdf2Sync(password, salt, 10000, 512, 'sha512').toString('hex');

    if (inputHash === hash) {
      // Successful login
      return res.status(200).send({ message: 'Login successful', data: user });
    } else {
      // Incorrect password
      return res.status(401).send({ message: 'Invalid credentials' });
    }
  } catch (err) {
    if (err.name === 'MongoServerError' && err.code === 11000) {
      // Duplicate key error: username already exists
      return res.status(409).send({ message: 'Username already exists' });
    } else {
      // Other server errors
      console.log(err);
      return res.status(500).send({ message: 'Server error' });
    }
  }
});


//api endpoint for creating a project
app.post('/api/createProject', async (req, res) => {
  console.log("Create project request: ", req.body.description)
  const name = req.body.name;
  const description = req.body.description;
  const cores = req.body.cores;
  const memory = req.body.memory;
  const disk = req.body.disk;

  

  if (!name || !description || !cores || !memory || !disk) {
    console.log("invalid request with name: ", name, " description: ", description, " cores: ", cores, " memory: ", memory, " disk: ", disk)
    // return res.status(400).send({ message: 'Invalid request' });
  }

  try {
    const newProject = new Project({ name: name, description: description, cores: cores, memory: memory, disk: disk });

    await newProject.save();

    return res.status(201).send({ message: 'Project created successfully' });
  } catch (err) {
    console.log(err);
    return res.status(500).send({ message: 'Server error' });
  }
});

//api endpoint for getting all projects
app.get('/api/getProjects', async (req, res) => {
  try {
    const projects = await Project.find().exec();
    return res.status(200).send({ data: projects });
  } catch (err) {
    return res.status(500).send({ message: 'Server error' });
  }
});

// api endpoint for creating a VM, A projectId and userId will also be available in the body, these should be used to link to documents in the user and project collections
app.post('/api/createVM', async (req, res) => {
  const image = req.body.image;
  const name = req.body.name;
  const privNetworkIP = req.body.privNetworkIP;
  const serverType = req.body.serverType;
  const projectId = req.body.projectId;
  const userId = req.body.userId;
  const cores = req.body.cores;
  const memory = req.body.memory;
  const disk = req.body.disk;
  const description = req.body.description


  if (!image || !name || !privNetworkIP || !serverType ||  !projectId || !cores || !memory || !disk || !projectId ) {
    return res.status(400).send({ message: 'Invalid request' });
  }

  try {
    const newVM = new VM({ image, name, description, privNetworkIP, serverType, projectId, cores, memory, disk });

    await newVM.save();

    return res.status(201).send({ message: 'VM created successfully' });
  } catch (err) {
    return res.status(500).send({ message: 'Server error' });
  }
});

//api endpoint for getting all VMs
app.get('/api/vmList', async (req, res) => {
  try {
    const vms = await VM.find().exec();
    return res.status(200).send({ data: vms });
  } catch (err) {
    return res.status(500).send({ message: 'Server error' });
  }
});

app.delete('/api/deleteVM/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const vm = await VM.findByIdAndDelete(id).exec();

    if (!vm) {
      return res.status(404).send({ message: 'VM not found' });
    }

    return res.status(200).send({ message: 'VM deleted successfully' });
  } catch (err) {
    return res.status(500).send({ message: 'Server error' });
  }
});

//api endpoint for getting the count of cores, memory and disk for all VMs grouped by projectId
app.get('/api/project/getUsedResources', async (req, res) => {
  console.log("Get used resources")
  try {
    const resources = await VM.aggregate([
      {
        $group: {
          _id: "$projectId",
          cores: { $sum: "$cores" },
          memory: { $sum: "$memory" },
          disk: { $sum: "$disk" }
        }
      }
    ]).exec();
    console.log(resources)
    return res.status(200).send({ data: resources });
  } catch (err) {
    return res.status(500).send({ message: 'Server error' });
  }
});



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
