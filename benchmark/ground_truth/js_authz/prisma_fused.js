app.get('/doc/:id', async (req, res) => {
  const doc = await prisma.doc.findUnique({
    where: { id: req.params.id, ownerId: req.user.id },
  });
  res.json(doc);
});
