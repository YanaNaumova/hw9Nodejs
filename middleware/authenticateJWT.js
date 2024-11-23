import jwt from "jsonwebtoken";
import "dotenv/config";

const jwtSecret = process.env.JWT_SECRET;
console.log(jwtSecret);
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Forbidden:Invalid or expired token" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: "Unautoriziert: No token provided" });
  }
}

export default authenticateJWT;
