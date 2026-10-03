import runner from './shell.js';
app.get('/x', (req, res) => {
  const q = req.query.q;
  runner(q);
});
