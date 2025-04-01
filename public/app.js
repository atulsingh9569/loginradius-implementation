require("dotenv").config({ path: "auth.env" });
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LOGINRADIUS_API_KEY;
const API_SECRET = process.env.LOGINRADIUS_API_SECRET;
const LOGINRADIUS_DOMAIN = process.env.LOGINRADIUS_DOMAIN;
const REDIRECT_URI = process.env.REDIRECT_URI;

app.use(cors({ origin: "http://localhost:5500" })); // Restrict to frontend origin
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Get Fresh SOTT
async function getSOTT() {
    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/manage/account/sott?apikey=${API_KEY}&apisecret=${API_SECRET}`;
        const response = await axios.get(url);
        return response.data.Sott;
    } catch (error) {
        console.error("Error fetching SOTT:", error.response?.data || error.message);
        throw new Error("Failed to retrieve SOTT");
    }
}

app.use(express.static("public")); // Serve frontend files

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

// Register User with Dynamic SOTT
app.post("/register", async (req, res) => {
    const { email, password, firstName, lastName, userName } = req.body;

    try {
        if (!email || !password || !userName) {
            return res.status(400).json({ error: "Missing required fields." });
        }

        const sott = await getSOTT();
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/register?apikey=${API_KEY}&verificationurl=${REDIRECT_URI}`;

        const headers = { "X-LoginRadius-Sott": sott, "Content-Type": "application/json" };
        const payload = {
            Email: [{ Type: "Primary", Value: email }],
            Password: password,
            FirstName: firstName || "John",
            LastName: lastName || "Doe",
            UserName: userName
        };

        const response = await axios.post(url, payload, { headers });
        res.json({ message: "Registration successful!", data: response.data });
    } catch (error) {
        console.error("Registration Error:", error.response?.data || error.message);
        res.status(400).json({ error: "Registration failed" });
    }
});

// Email Verification
app.get("/verify", async (req, res) => {
    const verificationToken = req.query.vtoken;
    if (!verificationToken) return res.status(400).json({ error: "Missing verification token." });

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/email?apikey=${API_KEY}&verificationtoken=${verificationToken}`;
        const response = await axios.get(url);
        res.json({ message: "Email verified!", data: response.data });
    } catch (error) {
        res.status(400).json({ error: "Email verification failed" });
    }
});

// Login User
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/login?apikey=${API_KEY}`;
        const response = await axios.post(url, { email, password });

        // Handle profile data safely
        const profile = response.data.Profile || {};
        const userEmail = (profile.Email && profile.Email.length > 0) ? profile.Email[0].Value : "No Email"; // Correctly extract email

        res.json({
            message: "Login successful!",
            data: {
                access_token: response.data.access_token,
                Profile: {
                    FullName: profile.FullName || "N/A",
                    UserName: profile.UserName || "N/A",
                    Email: userEmail // Include the extracted email
                }
            }
        });
    } catch (error) {
        console.error("Login Error:", error.response?.data || error.message);
        res.status(400).json({ error: "Login failed." });
    }
});

// Validate Access Token
app.get("/validate-token", async (req, res) => {
    const accessToken = req.query.token;
    if (!accessToken) return res.status(400).json({ error: "Missing access token." });

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/account`;
        const headers = { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" };
        
        const response = await axios.get(url, { headers });
        res.json({ message: "Token is valid!", data: response.data });
    } catch (error) {
        res.status(401).json({ error: "Invalid or expired token." });
    }
});

// Delete User Account
app.post("/delete", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

    try {
        const loginUrl = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/login?apikey=${API_KEY}`;
        const loginResponse = await axios.post(loginUrl, { email, password });
        const accessToken = loginResponse.data.access_token;

        const deleteUrl = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/account?apikey=${API_KEY}`;
        const headers = { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" };

        await axios.delete(deleteUrl, { headers });
        res.json({ message: "Account deleted successfully!" });
    } catch (error) {
        console.error("Account Deletion Error:", error.response?.data || error.message);
        res.status(400).json({ error: "Account deletion failed." });
    }
});

// Logout User
app.get("/logout", async (req, res) => {
    const accessToken = req.query.token;
    if (!accessToken) return res.status(400).json({ error: "Missing access token." });

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/access_token/invalidate?access_token=${accessToken}`;
        await axios.get(url);
        res.json({ message: "Logout successful!" });
    } catch (error) {
        res.status(400).json({ error: "Logout failed" });
    }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));