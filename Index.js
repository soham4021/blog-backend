const express = require("express");
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const User = require("./models/User");
const Post = require("./models/Post");
const bcrypt = require("bcryptjs");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const uploadMiddleware = multer({ dest: "uploads/" });
require("dotenv").config();
const fs = require("fs");
const BASE_URL = process.env.BASE_URL;

app.use(cors({ credentials: true, origin: `${BASE_URL}` }));
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));

const salt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET;

mongoose
	.connect(process.env.MONGO_URL)
	.then(() => console.log("MONGODB CONNECTED"))
	.catch((err) => console.log(err.message));

app.get("/test", (req, res) => {
	res.json("test ok");
});

app.post("/register", async (req, res) => {
	const { username, password } = req.body;
	try {
		const userDoc = await User.create({
			username,
			password: bcrypt.hashSync(password, salt),
		});
		res.json(userDoc);
	} catch (err) {
		console.log(err.message);
		res.status(400).json(err);
	}
});

app.post("/login", async (req, res) => {
	const { username, password } = req.body;
	const userDoc = await User.findOne({ username });
	const passOk = bcrypt.compareSync(password, userDoc.password);
	if (passOk) {
		//user is successfully logged in
		jwt.sign({ username, id: userDoc._id }, jwtSecret, {}, (err, token) => {
			if (err) throw err;
			res.cookie("token", token).json({
				id: userDoc._id,
				username,
			});
		});
	} else {
		//Unable to login
		res.status(400).json("Wrong credentials, unable to login");
	}
});

app.get("/profile", (req, res) => {
	const { token } = req.cookies;
	try {
		jwt.verify(token, jwtSecret, {}, (err, info) => {
			if (err) throw err;
			res.json(info);
		});
	} catch (error) {
		console.log(error.message);
	}
});

app.post("/logout", (req, res) => {
	res.cookie("token", "").json("ok");
});

app.post("/post", uploadMiddleware.single("file"), async (req, res) => {
	//file was the name of our data label in formData inside createPost.jsx
	//to grab the image file from the request to CREATE a post we'll need a library called multer
	const { originalname, path } = req.file;
	const parts = originalname.split(".");
	const ext = parts[parts.length - 1];
	const newPath = path + "." + ext;
	fs.renameSync(path, newPath);

	const { token } = req.cookies;
	jwt.verify(token, jwtSecret, {}, async (err, info) => {
		if (err) throw err;
		const { title, summary, content } = req.body;
		const postDoc = await Post.create({
			title,
			summary,
			content,
			cover: newPath,
			author: info.id,
		});
		res.json(postDoc);
	});
});

app.get("/post", async (req, res) => {
	const posts = await Post.find()
		.populate("author", ["username"])
		.sort({ createdAt: -1 })
		.limit(20);
	res.json(posts);
});

app.get("/post/:id", async (req, res) => {
	// res.json(req.params);
	const { id } = req.params;
	const postDoc = await Post.findById(id).populate("author", ["username"]);
	res.json(postDoc);
});

app.put("/post", uploadMiddleware.single("file"), async (req, res) => {
	let newPath = null;
	if (req.file) {
		const { originalname, path } = req.file;
		const parts = originalname.split(".");
		const ext = parts[parts.length - 1];
		newPath = path + "." + ext;
		fs.renameSync(path, newPath);
	}

	const { token } = req.cookies;
	jwt.verify(token, jwtSecret, {}, async (err, info) => {
		if (err) throw err;
		const { id, title, summary, content } = req.body;
		const postDoc = await Post.findById(id);
		const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
		if (!isAuthor) {
			return res.status(400).json("you are not the author");
		}
		await postDoc.update({
			title,
			summary,
			content,
			cover: newPath ? newPath : postDoc.cover,
		});

		res.json(postDoc);
	});
});

app.listen(4000, () => {
	console.log("Server started");
});
