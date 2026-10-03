router.get('/doc/:id', async (ctx) => {
  const doc = await Doc.findById(ctx.params.id);
  if (doc.ownerId !== ctx.state.user.id) ctx.throw(403);
  ctx.body = doc;
});
