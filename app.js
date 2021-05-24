const express = require("express");
const app = express();

app.use(express.json());
const {
	models: { User, Note },
} = require("./db");
const path = require("path");
const requireToken = async function (req, res, next) {
	try {
		const token = req.headers.authorization;
		const user = await User.byToken(token);
		req.user = user;
		next();
	} catch (err) {
		next(err);
	}
};
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.get("/api/users/:id/notes", requireToken, async (req, res, next) => {
	try {
		const notes = await req.user.getNotes();
		res.json(notes);
	} catch (err) {
		next(err);
	}
});

app.post("/api/auth", async (req, res, next) => {
	try {
		res.send({ token: await User.authenticate(req.body) });
	} catch (ex) {
		next(ex);
	}
});

app.get("/api/auth", requireToken, async (req, res, next) => {
	try {
		res.send(req.user);
	} catch (ex) {
		next(ex);
	}
});

app.use((err, req, res, next) => {
	console.log(err);
	res.status(err.status || 500).send({ error: err.message });
});

module.exports = app;
