const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../data/database");

const router = express.Router();

// Render welcome page
router.get("/", function (req, res) {
  res.render("welcome");
});

// Render signup page
router.get("/signup", function (req, res) {
  const sessionInputData = req.session.inputData || {
    hasError: false,
    email: "",
    confirmEmail: "",
    password: "",
  };

  req.session.inputData = null;
  res.render("signup", { inputData: sessionInputData });
});

// Render login page
router.get("/login", function (req, res) {
  const sessionInputData = req.session.inputData || {
    hasError: false,
    email: "",
    password: "",
  };

  req.session.inputData = null;
  res.render("login", { inputData: sessionInputData });
});

// Signup route
router.post("/signup", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password.trim();

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.length < 6 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.includes("@")
  ) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid input - please check your data 😸",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    return req.session.save(function () {
      res.redirect("/signup");
    });
  }

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User already exists 🙃",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    return req.session.save(function () {
      res.redirect("/signup");
    });
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  await db.getDb().collection("users").insertOne({
    email: enteredEmail,
    password: hashedPassword,
  });

  res.redirect("/login");
});

// Login route
router.post("/login", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (!existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in, please check your credentials 🧐",
      email: enteredEmail,
      password: enteredPassword,
    };

    return req.session.save(function () {
      res.redirect("/login");
    });
  }

  const passwordsAreEqual = await bcrypt.compare(
    enteredPassword,
    existingUser.password,
  );

  if (!passwordsAreEqual) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in, please check your credentials 🧐",
      email: enteredEmail,
      password: enteredPassword,
    };

    return req.session.save(function () {
      res.redirect("/login");
    });
  }

  req.session.user = {
    id: existingUser._id.toString(),
    email: existingUser.email,
    isAdmin: existingUser.isAdmin,
  };
  req.session.isAuthenticated = true;

  req.session.save(function () {
    if (existingUser.isAdmin) {
      res.redirect("/admin");
    } else {
      res.redirect("/profile");
    }
  });
});

// Admin route
router.get("/admin", function (req, res) {
  if (!res.locals.isAuth || !res.locals.isAdmin) {
    return res.status(403).render("403");
  }
  res.render("admin");
});

// Profile route
router.get("/profile", function (req, res) {
  if (!res.locals.isAuth) {
    return res.status(401).render("401");
  }
  res.render("profile");
});

// Logout route
router.post("/logout", function (req, res) {
  req.session.destroy(function () {
    res.redirect("/");
  });
});

module.exports = router;
