import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Discovery = { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };
type Event = { at: string; type: string; data: Record<string, string> };
const presets = ["happy-path", "expired-session", "mfa-required", "scope-denied", "provider-down", "slow-provider", "refresh-expired"];

function App() {
  const [discovery, setDiscovery] = useState<Discovery>();
  const [events, setEvents] = useState<Event[]>([]);
  const [scenario, setScenario] = useState("happy-path");
  const [error, setError] = useState("");
  async function refresh() {
    try {
      const [d, e] = await Promise.all([fetch("/.well-known/openid-configuration"), fetch("/admin/events")]);
      if (!d.ok || !e.ok) throw new Error("Unable to load local control-plane data.");
      setDiscovery(await d.json()); setEvents(await e.json()); setError("");
    } catch (x) { setError(x instanceof Error ? x.message : "Request failed"); }
  }
  async function choose(name: string) {
    const response = await fetch("/admin/scenario", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    if (!response.ok) { setError("Scenario update failed."); return; }
    setScenario(name); await refresh();
  }
  useEffect(() => { void refresh(); }, []);
  return <main className="mx-auto max-w-6xl p-6 text-slate-100">
    <header className="mb-8 border-b border-slate-800 pb-5"><p className="text-cyan-300">AuthCrate</p><h1 className="text-3xl font-semibold">Authentication sandbox for developers.</h1><p className="mt-2 text-slate-400">Live protocol inspection—not a mocked login UI.</p></header>
    {error && <p className="mb-4 rounded bg-red-950 p-3 text-red-200">{error}</p>}
    <section className="grid gap-5 md:grid-cols-2">
      <article className="panel"><h2>Protocol endpoints</h2>{discovery ? <dl>{Object.entries(discovery).map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl> : <p>Loading discovery…</p>}</article>
      <article className="panel"><h2>Scenario engine</h2><p className="mb-3 text-slate-400">The selected preset changes endpoint behavior immediately.</p><div className="flex flex-wrap gap-2">{presets.map(x=><button className={scenario===x?"active":""} onClick={()=>void choose(x)} key={x}>{x}</button>)}</div></article>
    </section>
    <section className="panel mt-5"><div className="flex items-center justify-between"><h2>Protocol events</h2><button onClick={()=>void refresh()}>Refresh</button></div><table><thead><tr><th>Time</th><th>Event</th><th>Metadata</th></tr></thead><tbody>{events.slice().reverse().map((e,i)=><tr key={i}><td>{new Date(e.at).toLocaleTimeString()}</td><td>{e.type}</td><td><code>{JSON.stringify(e.data)}</code></td></tr>)}</tbody></table></section>
  </main>;
}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
