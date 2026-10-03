app.get('/doc/:id', async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.ownerId !== req.user.id) return res.sendStatus(403);
  res.json(doc);
});
