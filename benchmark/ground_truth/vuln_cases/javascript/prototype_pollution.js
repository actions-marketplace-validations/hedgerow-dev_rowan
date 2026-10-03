function mergeSettings(target, req) {
  Object.assign(target, req.body);
  return target;
}
