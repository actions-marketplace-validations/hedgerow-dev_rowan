const express = require("express");
const { runFixed } = require("./shell");

const app = express();

app.get("/run", (req, res) => {
  const q = req.query.q;
  runFixed(q);
  res.send(q);
});
