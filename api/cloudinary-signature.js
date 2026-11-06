import { createRemoteJWKSet, jwtVerify } from "jose";
import { createHash } from "node:crypto";

const ADMIN_UID = "khw0e6GUkZZReBQ9kl7xlgiQzNfN2";
const PROJECT_ID = "qr-digital-menu-72c1f";
const JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://securetoken.google.com/${PROJECT_ID}`,
      audience: PROJECT_ID
    });

    if (payload.sub !== ADMIN_UID) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).json({ error: "Cloudinary environment variables are missing" });
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = "qasr-el-sham/menu-items";
    const paramsToSign = `folder=${folder}&timestamp=${timestamp}`;
    const signature = createHash("sha1")
      .update(paramsToSign + apiSecret)
      .digest("hex");

    return res.status(200).json({ cloudName, apiKey, timestamp, folder, signature });
  } catch (error) {
    console.error("Cloudinary signature error:", error);
    return res.status(401).json({ error: "Invalid authentication token" });
  }
}
