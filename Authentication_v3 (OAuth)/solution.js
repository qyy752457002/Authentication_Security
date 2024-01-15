import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
// import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import crypto from "crypto";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
// const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
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

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {

  /*
    req.user 来自于使用 passport.use(new Strategy(...)) 设置的 Passport 认证策略。
    当一个用户通过 Passport 的登录认证后，Passport 会自动将用户的信息添加到请求（req）对象中
  */
  console.log(req.user);

  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  };
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {

      // Hashing the password and saving it in the database

      // bcrypt.hash(password, saltRounds, async (err, hash) => {
      //   if (err) {
      //     console.error("Error hashing password:", err);
      //   } else {
      //     console.log("Hashed Password:", hash);
      //     const result = await db.query(
      //       "INSERT INTO users (email, password) VALUES ($1, $2)",
      //       [email, hash]
      //     );

      //     const user = result.rows[0];

      //     req.login(user, (err) => {
      //       console.log("success");
      //       res.redirect("/secrets");
      //     });
      //   }
      // });

      const salt = crypto.randomBytes(16).toString('hex');
      crypto.pbkdf2(password, salt, 100000, 64, 'sha512', async (err, derivedKey) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const hash = derivedKey.toString('hex');
          const result = await db.query(
            "INSERT INTO users (email, password, salt) VALUES ($1, $2, $3) RETURNING *",
            [email, hash, salt]
          );

          const user = result.rows[0];

          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Google登录
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// 常规登录
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// 自动获取用户在登录时 (往服务器发送 /login 的http请求)，表单中提交的 username 与 password
// cb 为 回调函数
passport.use("local",
  new Strategy(async function verify(username, password, cb) {

    console.log(username);
    console.log(password);

    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;

        // Verifying the password

        // bcrypt.compare(password, storedHashedPassword, (err, result) => {
        //   if (err) {
        //     return cb(err);
        //   } else {
        //     if (result) {
        //       return cb(null, user);
        //     } else {
        //       return cb(null, false);
        //     }
        //   }
        // });

        const salt = user.salt;

        crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedKey) => {
          if (err) {
            return cb(err);
          }
          const hash = derivedKey.toString('hex');
          if (hash === storedHashedPassword) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        });

      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use("google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        // 数据库 表内 不存在 任何 匹配 当前email的 用户记录
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          // 返还新注册的用户
          return cb(null, newUser.rows[0]);
        // 数据库 表内 存在 匹配 当前email的 用户记录
        } else {
          // 返还用户
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// 在 Passport 中，序列化用户是指将用户的标识信息（例如用户ID或整个用户对象）存储到会话中的过程
passport.serializeUser((user, cb) => {
  cb(null, user);
});

// 在 Passport 中，反序列化用户是指从会话中检索用户的标识信息（例如用户ID或整个用户对象）并转换为用户对象的过程
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
