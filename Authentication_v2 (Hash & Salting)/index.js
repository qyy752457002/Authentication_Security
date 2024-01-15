import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
// import bcrypt from "bcrypt";
import crypto from "crypto";

const app = express();
const port = 3000;
// const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "qyy2614102",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {

      // ***Hashing the password and saving it in the database

      // bcrypt.hash(password, saltRounds, async (err, hash) => {
      //   if (err) {
      //     console.error("Error hashing password:", err);
      //   } else {
      //     console.log("Hashed Password:", hash);
      //     await db.query(
      //       "INSERT INTO users (email, password) VALUES ($1, $2)",
      //       [email, hash]
      //     );
      //     res.render("secrets.ejs");
      //   }
      // });

      // ***Hashing the password using MD5

      // const hash = crypto.createHash('md5').update(password).digest('hex');
      // console.log("MD5 Hashed Password:", hash);
      // await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hash]);
      // res.render("secrets.ejs");

      // ***Hashing the password using pbkdf2

      // Generate a salt
      const salt = crypto.randomBytes(16).toString('hex');

      crypto.pbkdf2(password, salt, 100000, 64, 'sha512', async (err, derivedKey) => {
        if (err) throw err;
        const hash = derivedKey.toString('hex');

        console.log("pbkdf2 Hashed Password:", hash);

        await db.query("INSERT INTO users (email, password, salt) VALUES ($1, $2, $3)", [email, hash, salt]);

        res.render("secrets.ejs");
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      // ***Verifying the password

      // bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
      //   if (err) {
      //     console.error("Error comparing passwords:", err);
      //   } else {
      //     if (result) {
      //       res.render("secrets.ejs");
      //     } else {
      //       res.send("Incorrect Password");
      //     }
      //   }
      // });

      // ***Verifying the password by comparing MD5 hash

      // const loginPasswordHash = crypto.createHash('md5').update(loginPassword).digest('hex');
      // if (loginPasswordHash === storedHashedPassword) {
      //   res.render("secrets.ejs");
      // } else {
      //   res.send("Incorrect Password");
      // }

      // ***Verifying the password by comparing pbkdf2 hash

      crypto.pbkdf2(loginPassword, user.salt, 100000, 64, 'sha512', (err, derivedKey) => {
        if (err) throw err;
        const loginPasswordHash = derivedKey.toString('hex');

        if (loginPasswordHash === storedHashedPassword) {
          res.render("secrets.ejs");

        } else {
          res.send("Incorrect Password");
        }
      });

    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

