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

/*

当然，这段代码是用于在Node.js中设置会话（session）配置的，特别是使用了`express-session`中间件。
这个代码片段用于为Express应用程序设置会话管理。这里是你使用的选项的简要解释：

1. `secret`: 这是用于签名会话ID cookie的秘密密钥。这对于应用程序的安全非常重要。
   这里的值 `"TOPSECRETWORD"` 是一个占位符，应该替换为一个实际的秘密字符串。

2. `resave`: 这个选项强制会话在每次请求时都重新保存，即使它们可能没有发生变化。
   在这段代码中，它被设置为 `false`，这意味着只有在会话被修改时，它才会被保存。

3. `saveUninitialized`: 这个选项强制保存未初始化的会话。
                        未初始化的会话是那些新的但未被修改的会话。
                        在这段代码中，它被设置为 `true`，这意味着即使会话是新的并且没有被修改，它也会被保存在存储中。

这些配置帮助确保了会话数据的安全性和有效管理。在实际应用中，你应该根据自己的需要调整这些设置。

*/
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    // 1000 毫秒 * 60 * 60 * 24
    maxAge: 1000 * 60 * 60 * 24
  }
}));

/*
这两行代码是在Node.js的Express框架中使用`passport`进行身份验证的配置。
`passport`是一个流行的中间件，用于在Node.js应用程序中处理身份验证。
以下是这两行代码的详细解释：

1. `app.use(passport.initialize())`: 这行代码初始化了`passport`。
    在你的Express应用程序中使用`passport`时，这是必需的。
    它负责初始化`passport`内部的一些设置，并准备好将来的身份验证请求。

2. `app.use(passport.session())`: 这行代码让`passport`支持持久的登录会话。
                                 它必须在`passport.initialize()`之后使用。
                                 这个中间件利用Express的会话（session）支持来保持用户的登录状态。
                                 当用户通过`passport`的身份验证策略成功登录后，用户的身份信息将被序列化到会话中，并在后续的请求中被反序列化以维持用户状态。

为了使这些代码正常工作，你需要在应用中已经配置了会话（如使用`express-session`)。
`passport`会使用这些会话信息来存储和检索用户的身份验证状态。

使用`passport`可以轻松地添加多种身份验证策略，如本地用户名和密码验证、OAuth（例如使用Google或Facebook登录），以及其他更多的认证方法。

*/
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

/*
这段代码是一个在Node.js的Express框架中使用的路由处理程序，用于管理对`/secrets`路径的访问。
这里使用了`passport`库来处理身份验证。下面是代码的详细解释：

- `app.get("/secrets", (req, res) => {...})`: 这行定义了一个路由处理程序，当客户端发送GET请求到`/secrets`路径时，它将被执行。
                                              `req`（请求对象）和`res`（响应对象）是Express中处理HTTP请求和响应的标准参数。

- `if (req.isAuthenticated()){...}`: `req.isAuthenticated()`是`passport`提供的一个方法，用来检查当前的用户是否已经通过身份验证。
                                      如果用户已经登录，这个方法将返回`true`。

- `res.render("Secrets.ejs")`: 如果用户已经认证，即已经登录，那么代码将使用`res.render`方法来渲染`Secrets.ejs`文件。
                               `Secrets.ejs`是一个EJS模板文件，通常包含HTML和JavaScript，用于生成页面内容。
                               这里假设你的应用配置了EJS作为模板引擎。

- `res.redirect("/login")`: 如果用户未通过身份验证（即未登录），那么路由处理程序将用户重定向到登录页面。
                           `/login`是用户登录表单的路径。

这种方式确保了只有已认证的用户才能访问`/secrets`路径。
如果未认证的用户尝试访问此路径，他们将被重定向到登录页面，这是一个常见的Web应用安全做法。
*/
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

/*

### Passport.js 和会话（Session）

Passport.js 是 Node.js 的一个身份验证库，用于简化用户认证过程。
它与会话紧密结合，会话是一种在服务器上存储信息的机制，通常用于跟踪用户的状态。
在基于 Node.js 的应用程序中，会话信息通常存储在服务器的内存中、数据库中或者使用专门的会话存储解决方案。

### `serializeUser` 函数

- **作用**: 当用户通过身份验证时，`serializeUser` 决定哪些用户信息应存储在会话中。
            这是为了减少每个请求所需的数据量并提高性能。
- **过程**:
   - 当用户登录并且身份验证成功后，`serializeUser` 被调用。
   - 在这个函数内，你可以选择存储用户的某些信息（通常是用户ID）到会话中。
   - 存储的信息通常是唯一的，可以在以后的请求中用来标识用户。

- **会话存储**:
   - 当 `cb` 被调用时，用户ID 被存储在会话存储中，比如内存、Redis、数据库等。
   - 这个 ID 随后被发送到用户的浏览器并存储在 cookie 中。

### `deserializeUser` 函数

- **作用**: 在后续的每个请求中，`deserializeUser` 用于从会话中检索用户的完整数据。
- **过程**:
   - 在每个请求中，Express.js 会从用户的 cookie 中读取会话ID，并使用它来找到服务器上的会话。
   - `deserializeUser` 被调用，传入存储在会话中的信息（例如用户ID）。
   - 你可以使用这个ID从数据库或其他存储中检索用户的完整信息。

- **用户信息的检索**:
   - 通过 `deserializeUser`，用户的完整信息被检索并添加到每个请求对象中，通常作为 `req.user`。

### 总结

总的来说，`serializeUser` 和 `deserializeUser` 在 Passport.js 的用户认证过程中扮演关键角色。
`serializeUser` 在用户初次登录时运行，选择性地将用户信息（如ID）存储到会话中。
`deserializeUser` 则在后续请求中运行，使用存储在会话中的信息来检索用户的完整数据。

这个过程确保了应用可以有效地管理用户状态，同时保持高效和安全。
通过只在会话中存储必要的信息（如用户ID），应用能够减少每个请求的处理负担，同时避免将敏感信息存储在客户端。

*/

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

