import express from "express";
import "dotenv/config";
import cors from "cors";
import sequelize from "./config/db.js";
import User from "./models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import authenticateJWT from "./middleware/authenticateJWT.js";
import changePassword from "./middleware/changePassword.js";
import authorizeRole from "./middleware/authorizeRole.js";

const port = process.env.PORT;
const jwtSecret = process.env.JWT_SECRET;
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/register", async (req, res) => {
  const { email, password, username, role, mustChangePassword } = req.body;
  try {
    if (!email || !password || !username || !role || !mustChangePassword) {
      return res.status(403).json({ message: "All fields are required" });
    }
    const uniqueEmail = await User.findOne({ where: { email: email } });
    if (uniqueEmail) {
      return res
        .status(409)
        .json({ message: "The user with this email already exists" });
    }
    const heshedPassword = await bcrypt.hash(password, 5);
    const newUser = await User.create({
      email,
      password: heshedPassword,
      username,
      role,
      mustChangePassword,
    });
    res.status(201).json({
      message: "user was successful register",
      user: newUser.username,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res
        .status(403)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      return res.status(404).json({ message: "User was not found" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorrect password" });
    }
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        mustChangePassword: user.mustChangePassword,
      },
      jwtSecret,
      { expiresIn: "1h" }
    );
    res
      .status(200)
      .json({ message: `User ${user.username} was logged`, token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

app.get("/profile", authenticateJWT, changePassword, async (req, res) => {
  const userId = req.user.id;
  try {
    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    res.status(200).json({ user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

app.post("/change-password", authenticateJWT, async (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(403).json({ message: "Password are required" });
  }
  const userId = req.user.id;
  try {
    const heshedPassword = await bcrypt.hash(password, 5);
    const affectedRows = await User.update(
      { password: heshedPassword, mustChangePassword: false },
      { where: { id: userId } }
    );
    if (affectedRows === 0) {
      return res.status(404).json({ message: "user was not found" });
    }
    res.status(201).json({ message: "user was updated" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

app.post("/delete-account", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { password } = req.body;
  try {
    if (!password) {
      return res.status(403).json({ message: "Password are required" });
    }
    const user = await User.findOne({ where: { id: userId } });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorrect password" });
    }
    const numberOfDeletedRows = await User.destroy({
      where: { id: userId },
    });
    if (numberOfDeletedRows > 0) {
      return res
        .status(200)
        .json({ message: `User with id ${userId} was deleted` });
    } else {
      return res
        .status(404)
        .json({ message: `User with ID ${userId} not found` });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

app.get("/admin", authenticateJWT, authorizeRole("admin"), (req, res) => {
  res.status(200).json({ message: "Hey Admin" });
});

app.post("/change-email", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res
        .status(403)
        .json({ message: "Email and password are required" });
    }
    const emailExists = await User.findOne({ where: { email: email } });
    if (emailExists) {
      return res
        .status(409)
        .json({ message: "This email is already existiert" });
    }
    const user = await User.findOne({ where: { id: userId } });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorect password" });
    }
    const [numberOfAffectedRows] = await User.update(
      { email },
      { where: { id: userId } }
    );

    if (numberOfAffectedRows > 0) {
      return res.status(200).json({ message: `User ID ${userId} was updated` });
    } else {
      return res
        .status(404)
        .json({ message: `User with ID ${userId} not found` });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.listen(port, () => {
  try {
    sequelize.authenticate();
    console.log("Connected with DB was successfuly");
    console.log(`Server running on http://127.0.0.1:${port}`);
  } catch (error) {
    console.log(error);
  }
});
