const Sequelize = require("sequelize");
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.JWT;
const { STRING } = Sequelize;
const bcrypt = require("bcrypt");

const config = {
	logging: false,
};

if (process.env.LOGGING) {
	delete config.logging;
}
const conn = new Sequelize(
	process.env.DATABASE_URL || "postgres://localhost/acme_db",
	config
);

const User = conn.define("user", {
	username: STRING,
	password: STRING,
});
const Note = conn.define("note", {
	text: STRING,
});

User.addHook("beforeCreate", async (user) => {
	const SALT_COUNT = 7;
	const hashedPwd = await bcrypt.hash(user.password, SALT_COUNT);
	user.password = hashedPwd;
});

User.byToken = async (token) => {
	try {
		const data = await jwt.verify(token, SECRET_KEY);
		const user = await User.findByPk(data.userId);
		if (user) {
			return user;
		}
		const error = Error("bad credentials");
		error.status = 401;
		throw error;
	} catch (ex) {
		const error = Error("bad credentials");
		error.status = 401;
		throw error;
	}
};
User.hasMany(Note);
Note.belongsTo(User);
User.authenticate = async ({ username, password }) => {
	const user = await User.findOne({
		where: {
			username,
		},
	});
	const isValid = await bcrypt.compare(password, user.password);
	if (isValid) {
		const token = await jwt.sign({ userId: user.id }, SECRET_KEY);
		return token;
	}
	const error = Error("bad credentials");
	error.status = 401;
	throw error;
};

const syncAndSeed = async () => {
	await conn.sync({ force: true });
	const credentials = [
		{ username: "lucy", password: "lucy_pw" },
		{ username: "moe", password: "moe_pw" },
		{ username: "larry", password: "larry_pw" },
		{ username: "rocky", password: "rocketdog" },
	];
	const [lucy, moe, larry, rocky] = await Promise.all(
		credentials.map((credential) => User.create(credential))
	);
	const notes = [
		{ text: "wow", userId: 1 },
		{
			text: "amazing",
			userId: 1,
		},
		{
			text: "the straight man stooge",
			userId: 2,
		},
		{ text: "just another stooge", userId: 3 },
	];
	const [note1, note2, note3, note4] = await Promise.all(
		notes.map((note) => Note.create(note))
	);
	return {
		users: {
			lucy,
			moe,
			larry,
			rocky,
		},
		notes: {
			note1,
			note2,
			note3,
			note4,
		},
	};
};

module.exports = {
	syncAndSeed,
	models: {
		User,
		Note,
	},
};
