import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = searchParams.get("ip");

  const userId = process.env.NEUTRINO_USER_ID;
  const apiKey = process.env.NEUTRINO_API_KEY;

  if (!userId || !apiKey || !ip) {
    return NextResponse.json({ error: "Missing config or IP" }, { status: 400 });
  }

  const formData = new URLSearchParams();
  formData.append("ip", ip);

  try {
    const neutrinoRes = await fetch("https://neutrinoapi.net/ip-blocklist", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        "user-id": userId,
        "api-key": apiKey,
        ip,
      }),
    });

    if (!neutrinoRes.ok) {
      const errorText = await neutrinoRes.text();
      console.error("Neutrino API failed:", errorText);
      return NextResponse.json({ error: "Neutrino API error" }, { status: 500 });
    }

    const data = await neutrinoRes.json();
    return NextResponse.json(data);
  } catch (err) {
    console.error("Neutrino Fetch Error:", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
