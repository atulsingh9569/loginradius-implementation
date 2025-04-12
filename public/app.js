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

app.use(express.static("public")); // Serve frontend files

// Get Fresh SOTT (Security Token for Registration)
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

// Serve frontend
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

// Register User
app.post("/register", async (req, res) => {
    const { email, password, firstName, lastName, userName } = req.body;

    try {
        if (!email || !password || !userName) {
            return res.status(400).json({ error: "Missing required fields." });
        }

        const sott = await getSOTT();

        const url = `https://api.loginradius.com/identity/v2/auth/register?apikey=${API_KEY}&verificationurl=${REDIRECT_URI}`;

        const headers = { 
            "X-LoginRadius-Sott": sott,
            "Content-Type": "application/json"
        };

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
        res.status(400).json({ error: "Registration failed", details: error.response?.data });
    }
});

// Verify Email - GET Request
app.get("/verify", async (req, res) => {
    const verificationToken = req.query.verificationtoken;

    if (!verificationToken) {
        return res.status(400).json({ error: "Missing verification token." });
    }

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/email?apikey=${API_KEY}&verificationtoken=${verificationToken}`;
        const response = await axios.get(url);
        
        res.json({ message: "Email verified!", data: response.data });
    } catch (error) {
        console.error("Email verification failed:", error.response?.data || error.message);
        res.status(400).json({ error: "Email verification failed" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        const url = `${LOGINRADIUS_DOMAIN}/identity/v2/auth/login?apikey=${API_KEY}`;
        const payload = { email, password };

        const response = await axios.post(url, payload, { headers: { "Content-Type": "application/json" } });

        const profile = response.data.Profile || {};
        const userEmail = (profile.Email && profile.Email.length > 0) ? profile.Email[0].Value : "No Email";

        res.json({
            message: "Login successful!",
            data: {
                access_token: response.data.access_token,
                Profile: {
                    UserName: profile.UserName || "User",
                    Email: profile.Email || []
                }
            }
        });
    } catch (error) {
        console.error("Login Error:", error.response?.data || error.message);
        res.status(400).json({ error: "Login failed", details: error.response?.data });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
