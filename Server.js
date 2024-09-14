const bcrypt = require('bcryptjs'); // أو 'bcrypt' إذا قمت بتثبيته
const jwt = require('jsonwebtoken');
const cors = require('cors');
const express = require('express');
const app = express();
const port = 3000;

const user = {
  username: "admin",
  name: "Hossam Shaaban",
  password: "password123",
  email: "scob198350@gmail.com",
  avatar:
    "https://scontent.fcai22-4.fna.fbcdn.net/v/t39.30808-1/434458080_941527470760747_3949449511034126485_n.jpg?stp=c72.0.174.173a_dst-jpg_p320x320&_nc_cat=104&ccb=1-7&_nc_sid=50d2ac&_nc_eui2=AeG4qzdk84CZer7j_WiUgr1zhpdmoIaMv_WGl2aghoy_9Z7LdWXNIFsI30HPeS-8ZKm8jNMGrygjmxtgvhfvUSAU&_nc_ohc=czFF1FA1m2cQ7kNvgHN2ZI9&_nc_ht=scontent.fcai22-4.fna&_nc_gid=AImsJVGQ24CU_mcYdvkmX-x&oh=00_AYBG1HxQTdfMSNghhQedd_dGMXbHbJE5MU2futIlLWpXHA&oe=66EB9D08",
};

const secretKey = "your_secret_key";

app.use(express.json());
app.use(cors());

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (username !== user.username) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  const token = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: "1h",
  });

  res.json({
    message: "Logged in successfully",
    token,
    username: user.username,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
  });
});

app.get("/user", authenticateToken, (req, res) => {
  const { password, ...userWithoutPassword } = user; // استبعاد كلمة المرور من الاستجابة
  res.json(userWithoutPassword);
});

app.put("/user", authenticateToken, async (req, res) => {
  const { username, newPassword, email, avatar } = req.body;

  if (username !== user.username) {
    return res.status(400).json({ message: "Invalid username" });
  }

  if (newPassword) {
    user.password = await bcrypt.hash(newPassword, 10);
  }

  user.email = email || user.email;
  user.avatar = avatar || user.avatar;

  res.json({
    message: "User updated successfully",
    user: { username: user.username, email: user.email, avatar: user.avatar },
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}

app.listen(port, async () => {
  user.password = await bcrypt.hash(user.password, 10);
  console.log(`Server running at http://localhost:${port}`);
});
