import { getStore } from "@netlify/blobs";

export default async (req) => {
  const store = getStore("team-assign");
  if (req.method === "PUT") {
    const body = await req.text();
    try { JSON.parse(body); } catch { return new Response("bad json", { status: 400 }); }
    await store.set("state", body);
    return new Response("ok");
  }
  const v = await store.get("state");
  return new Response(v ?? "null", {
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
};

export const config = { path: "/api/state" };
