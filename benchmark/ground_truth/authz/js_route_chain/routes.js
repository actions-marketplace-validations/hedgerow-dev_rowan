const express = require("express");
const app = express();
const Doc = require("./models/doc");

app.route("/g/:id").get(auth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});

app.get("/ok/:id", auth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.ownerId !== req.user.id) return res.status(403).json({ error: "forbidden" });
  res.json(doc);
});
