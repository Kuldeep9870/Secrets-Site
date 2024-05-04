import express from "express";
import bodyParser from "body-parser";
import mongoose from 'mongoose';
import bcrypt from "bcrypt"
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv"
import GoogleStrategy from "passport-google-oauth2"
env.config();

let url =process.env.DB_URL;
mongoose.connect(url);

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  secret : String,
});

const User = new mongoose.model("User", userSchema);
const app = express();
const port = process.env.PORT;
const saltround=10;


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    // cookie:{
    //   maxAge:1000 *60*60 *24,
    // }
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/secrets", async (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    try {
        const result = await User.findOne({ username: req.user.username });
        console.log(result);
        // const secret = result.secret;
        if (result.secret) {
          res.render("secrets.ejs", { secret: result.secret });
        } else {
          res.render("secrets.ejs", { secret: "Enter your Secret !" });
        }
      } catch (err) {
        console.log("error - >"  + err);
      }
  } else {
    res.redirect("/login");
  }
});

app.get('/submit',(req,res)=>{
    if (req.isAuthenticated()) {
        res.render("submit.ejs");
      } else {
        res.redirect("/login");
      }
})

app.get("/login", (req, res) => {
  res.render("login.ejs");
});
 
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

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

app.post("/register", async (req, res) => {
  const Enteredusername = req.body.username;
  const Enteredpassword = req.body.password;
  const checkuser = await User.findOne({ username: Enteredusername });
  if(checkuser){
    res.send('User exists already');
  }
  else{
    bcrypt.hash(Enteredpassword,saltround, async (err,hash)=>{
      const user = await User.create({
        username: Enteredusername,
        password: hash,
      });
      req.login(user, (err) => {
        console.log("success");
        res.redirect("/secrets");
      });
    })
  }
  
});

app.post("/login",passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
})
);


app.post("/submit",async (req,res)=>{
    const submittedSecret = req.body.secret;
    console.log(req.user);
    try {
        const filter = { username: req.user.username };
        const update = { secret: submittedSecret };
        let doc= await User.findOneAndUpdate(filter, update,{new:true});
        // await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
        //   submittedSecret,
        //   req.user.email,
        // ]);
        res.redirect("/secrets");
      } catch (err) {
        console.log(err);
      }
})



app.get('/logout', function(req, res, next){
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});


passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const user = await User.findOne({ username: username });
      console.log(user);  
      if (user) {
        // const user = result.rows[0];
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

passport.use(
  "google",
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
        const result = await User.findOne({ username: profile.email });
        if (!result) {
          const newUser = await User.create({
            username: profile.email,
            password: "google",
          });
          return cb(null, newUser);
        } else {
          return cb(null, result);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
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
