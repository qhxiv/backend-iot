import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import mqtt from "mqtt";
import { Server } from "socket.io";
import { createServer } from "node:http";

const PORT = 8081;
const saltRounds = 10;
const jwtSecretKey = "jwt-secret-key";

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: "GET,POST,PUT,DELETE",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true,
  })
);
app.use(cookieParser());
const server = createServer(app);

// Socket server
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("User connected: ", socket.id);

  socket.on("disconnect", () => console.log("User disconnected: ", socket.id));
});

// Connect to mysql db
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "iot",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting database: " + err.stack);
    return;
  }

  console.log("Database connected as id " + db.threadId);
});

// Sign up
app.post("/signup", (req, res) => {
  const { email, username, password } = req.body;

  // Check if the sign up info is valid
  db.query(
    "SELECT username FROM user WHERE username = ?",
    [username],
    (err, result) => {
      if (err) console.log("Error getting data from db: ", err);
      if (result.length > 0)
        return res.json({
          message: "This username is already taken",
          success: false,
        });
    }
  );
  db.query(
    "SELECT username FROM user WHERE email = ?",
    [email],
    (err, result) => {
      if (err) console.log("Error getting data from db: ", err);
      if (result.length > 0)
        return res.json({
          message: "User with this email is already existed",
          success: false,
        });
    }
  );

  // Sign up info is valid
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err)
      return res.status(500).json({
        message: "Error hashing password: " + err,
        success: false,
      });

    db.query(
      "INSERT INTO user (email, username, password) VALUES (?)",
      [[email, username, hash]],
      (err) => {
        if (err) console.log("Error inserting data to db: ", err);
        return res.status(200).json({
          message: "Sign up successfully",
          success: true,
        });
      }
    );
  });
});

// Log in
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT password FROM user WHERE username = ?",
    [username],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Server error", success: false });

      if (results.length === 0)
        return res.json({ message: "Wrong username", success: false });

      bcrypt.compare(password, results[0].password, (err, result) => {
        if (err)
          return res
            .status(500)
            .json({ message: "Error comparing password", success: false });

        if (result) {
          const token = jwt.sign({ username }, jwtSecretKey, {
            expiresIn: "1d",
          });
          res.cookie("token", token);

          return res.json({ message: "Log in successfully", success: true });
        } else return res.json({ message: "Wrong password", success: false });
      });
    }
  );
});

// Verify user
function verifyUser(req, res, next) {
  const token = req.cookies.token;
  if (!token)
    return res.json({ message: "You are not authenticated", success: false });
  else {
    jwt.verify(token, jwtSecretKey, (err, decoded) => {
      if (err)
        return res.json({ message: "Token is not correct", success: false });
      else {
        req.username = decoded.username;
        next();
      }
    });
  }
}

app.get("/verify", verifyUser, (req, res) => {
  return res.json({
    message: "Authenticate successfully",
    username: req.username,
    success: true,
  });
});

// Log out
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Log out successfully", success: true });
});

// MQTT
const options = {
  host: "ffcfa4e2529e4f36b2a8dff69e2105e0.s1.eu.hivemq.cloud",
  port: 8883,
  protocol: "mqtts",
  username: "tunh1",
  password: "Huytu2003",
};

const client = mqtt.connect(options);

client.on("connect", () => {
  console.log("Mqtt connected");
});

client.on("error", (error) => {
  console.log(error);
});

client.subscribe("esp8266/client");
client.subscribe("esp8266/status");

// receive data from mqtt and send to frontend using socket.io
client.on("message", function (topic, message) {
  const data = JSON.parse(message.toString());
  if (topic === "esp8266/client") io.emit("client", data);
  else if (topic === "esp8266/status") io.emit("status", data);
});

// send data to mqtt
app.post("/send-mqtt", (req, res) => {
  try {
    client.publish("esp8266/fromWeb", JSON.stringify(req.body));
    // console.log(req.body);
    res.status(200).json({ message: "Sent data to mqtt", success: true });
  } catch (error) {
    console.log(error);
  }
});

server.listen(PORT, () => {
  console.log("Server is running at port " + PORT);
});
