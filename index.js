const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
require("dotenv").config();
const UserRouter = require("./route/UserRoute");

const PORT = process.env.PORT || 8000;
const app = express();

app.use(express.json());
app.use(bodyParser.json());
app.use(cors());
app.use("/user", UserRouter);

const dbURI = process.env.MONGODB_URI;

mongoose.connect(dbURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  socketTimeoutMS: 30000,
});

const connection = mongoose.connection;

connection.once("open", () => {
  console.log("Connected to MongoDB");
});

connection.on("error", (err) => {
  console.log("MongoDB connection error:", err);
});

app.get("/", (req, res) => {
  res.send("Server is running");
});

app.listen(PORT, () => {
  console.log(`Server is running at port ${PORT}`);
});
