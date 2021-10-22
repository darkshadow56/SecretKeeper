//////IMPORTS//////
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const {} = require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

//////DECLARATIONS/////

//////MIDDLEWARE//////
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname +'/public'));
mongoose.connect("mongodb://localhost:27017/userDB", () => {
  console.log("Database connected!");
});
app.use(
  session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

//////CREATING SCHEMA///////
const userSchema = new mongoose.Schema({
  userName: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

//////////////////
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//////CREATING MODEL///////
const User = mongoose.model("user", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  ////////////LOGIN WITH GOOGLE//////////////////
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    (request, accessToken, refreshToken, profile, done) => {
        console.log(profile);
      User.findOrCreate({ googleId: profile.id, userName: profile.displayName },  (err, user)=> {
        return done(err, user);
      });
    }
  )
);

///////////LOGIN WITH FACEBOOK//////////////////
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  (accessToken, refreshToken, profile, cb)=> {
    User.findOrCreate({ facebookId: profile.id }, (err, user)=> {
      return cb(err, user);
    });
  }
));
//////////////////////////////////


//////ROUTES//////////
app.get("/", (req, res) => {
  res.render("home");
});

//////////////Route to call google Auth api////////////////
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

///////////////response route from google auth////////////
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: "/secrets",
        failureRedirect: "/login"
})
);

/////////////ROUTE TO CALL FACEBOOK AUTH/////////////////
app.get('/auth/facebook',
  passport.authenticate('facebook'));


////////////RESPONSE ROUTE FROM FACEBOOK//////////////
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
                        failureRedirect: "/login",
                        successRedirect: "/secrets" }));
       
 
app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  const userName = req.body.username;
  const password = req.body.password;
  User.register({ username: userName }, password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});
app.post("/login", (req, res) => {
  const userName = req.body.username;
  const password = req.body.password;

  const user = new User({
    username: userName,
    password: password,
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        if (err) {
          console.log(err);
        } else {
          res.redirect("/secrets");
        }
      });
    }
  });
});
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
      User.find({"secret": {$ne: null}}, (err, allSecrets)=>{
        res.render("secrets", {userSecrets: allSecrets});        
      })
  } else {
    res.redirect("/login");
  }
});
app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
      } else {
        res.redirect("/login");
      }
});
app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  const sessionUser = req.user._id;
  User.findById(sessionUser, (err, foundUser)=>{
      if(err){
          console.log(err);
      }else{
          if(foundUser){
              foundUser.secret = submittedSecret;
              foundUser.save(()=>{
                  res.redirect("/secrets");
              });
          }
      }
  })
});
app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

app.listen(PORT, () => {
  console.log("Server started on", PORT);
});
