const express = require("express");
const app = express();
const Doc = require("./models/doc");

app.get("/a/:id", async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (!doc.owner.equals(req.user._id)) return res.status(403).json({ error: "forbidden" });
  res.json(doc);
});

app.get("/b/:id", async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.owner.toString() !== req.user.id) return res.status(403).json({ error: "forbidden" });
  res.json(doc);
});
