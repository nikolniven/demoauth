const express = require("express");
const { ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

// Render welcome page
router.get("/", function (req, res) {
  res.render("welcome");
});

// Render signup page
router.get("/signup", function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      confirmEmail: "",
      password: "",
    };
  }
  req.session.inputData = null;
  res.render("signup", { inputData: sessionInputData });
});

// Render login page
router.get("/login", function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      password: "",
    };
  }
  req.session.inputData = null;
  res.render("login", { inputData: sessionInputData });
});

// Signup route to create a new user
router.post("/signup", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password.trim();

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.trim() < 6 ||
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

    req.session.save(function () {
      return res.redirect("/signup");
    });
    return;
  }

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User exist already 🙃",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };
    req.session.save(function () {
      res.redirect("/signup");
    });
    return;
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };
  await db.getDb().collection("users").insertOne(user);

  res.redirect("/login");
});

// Login route to authenticate the user
router.post("/login", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  // Find the user by email
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
    req.session.save(function () {
      res.redirect("/login");
    });
    return;
  }

  // Compare the entered password with the stored password
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
    req.session.save(function () {
      res.redirect("/login");
    });
    return;
  }

  // Store user info in session
  req.session.user = {
    id: existingUser._id.toString(),
    email: existingUser.email,
    isAdmin: existingUser.isAdmin, // Store isAdmin flag in session
  };
  req.session.isAuthenticated = true;

  // Log session data before redirecting to check if everything is set correctly
  console.log("Session after login:", req.session); // Check session data

  // Save the session
  req.session.save(function () {
    console.log("Session saved successfully!");
    if (existingUser.isAdmin) {
      return res.redirect("/admin");
    } else {
      return res.redirect("/profile");
    }
  });
});

// Admin route: should only be accessed by admin users
router.get("/admin", async function (req, res) {
  console.log("Session in /admin route:", req.session);

  if (!req.session.isAuthenticated) {
    console.log("User is not authenticated, redirecting to 401");
    return res.status(401).render("401");
  }

  // Ensure that the user exists in the session
  const user = req.session.user;
  if (!user) {
    console.log("User not found in session, redirecting to 401");
    return res.status(401).render("401");
  }

  console.log("User object:", user);
  if (!user.isAdmin) {
    console.log("User is not an admin, redirecting to 403");
    return res.status(403).render("403");
  }

  res.render("admin");
});

// Profile route: should be accessible to authenticated users
router.get("/profile", function (req, res) {
  if (!req.session.isAuthenticated) {
    return res.status(401).render("401");
  }

  res.render("profile");
});

// Logout route to clear session and logout the user
router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;
