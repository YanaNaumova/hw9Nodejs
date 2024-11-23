function changePassword(req, res, next) {
  console.log(req.user.mustChangePassword);
  if (req.user.mustChangePassword === true) {
    return res.status(403).json({
      message:
        "You must change your password before logging in. Please visit /change-password",
    });
  }
  next();
}

export default changePassword;
