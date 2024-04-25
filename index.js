import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose"
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();


app.set('view engine', 'ejs');

app.use(
  session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://mongo_db:27017/user").then(() => console.log("connected"));
// mongoose.connect("mongodb://localhost:27017/user").then(() => console.log("connected"));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  number: Number,
  dob: Date
});

const user = mongoose.model("user", userSchema)

app.get("/", (req, res) => {
  res.render("home.ejs");
});
app.get("/auth", (req, res) => {
  res.render("auth.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/service1", (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("service1.ejs", {
      details: req.user
    });
  } else {
    res.redirect("/auth");
  }
});
app.get("/service2", (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("service2.ejs", {
      details: req.user
    });
  } else {
    res.redirect("/auth");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/auth",
  })
);


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const name = req.body.name;
  const dob = req.body.dob;
  const number = req.body.number;

  try {
    const checkResult = await user.findOne({ email: email });

    if (checkResult) {
      // User with this email already exists
      return res.redirect("/auth");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          return res.status(500).send("Internal Server Error");
        } else {
          try {
            const newUser = await user.create({
              name: name,
              email: email,
              password: hash,
              number: number,
              dob: dob
            });
            req.login(newUser, (err) => {
              if (err) {
                console.error("Error logging in:", err);
                return res.status(500).send("Internal Server Error");
              }
              console.log("Registration successful");
              return res.redirect("/");
            });
          } catch (err) {
            console.error("Error creating user:", err);
            return res.status(500).send("Internal Server Error");
          }
        }
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).send("Internal Server Error");
  }
});


passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await user.find({ email: username });
      if (result) {
        const user = result[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
