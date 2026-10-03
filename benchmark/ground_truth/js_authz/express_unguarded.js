app.use((req, res, next) => { req.user = auth(req); next(); });
app.get('/doc/:id', async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});
