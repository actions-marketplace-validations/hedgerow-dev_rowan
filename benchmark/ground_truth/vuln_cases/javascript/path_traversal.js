const fs = require("fs");
const express = require("express");
const app = express();

app.get("/download", (req, res) => {
  const data = fs.readFileSync("/srv/files/" + req.query.name);
  res.send(data);
});
