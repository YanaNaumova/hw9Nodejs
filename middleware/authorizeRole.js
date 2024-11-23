function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role === role) {
      next();
    } else {
      return res.status(403).json({
        message: "Forbidden: you do not have access to this resourse",
      });
    }
  };
}

export default authorizeRole;
