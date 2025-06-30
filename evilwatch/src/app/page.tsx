"use client";
import Image from "next/image";
import { useState, useEffect } from 'react';
import {
  FaLock, FaDatabase, FaSearch, FaGlobe, FaShieldAlt
} from 'react-icons/fa';
import { FaTimes } from 'react-icons/fa';


type GeoInfo = {
  ip: string;
  country: string;
  city: string;
  isp: string;
  lat?: number;
  lon?: number;
} | null;

type ThreatInfo = {
  value: string;
  category: string;
  source: string;
  severity: string;
  notes: string;
} | null;

type NeutrinoInfo = {
  blocklist?: boolean;
  reason?: string;
  country?: string;
  host?: string;
} | null;

type CVE = { title: string; link: string; };
type RawCVE = { title?: string; name?: string; cve_id?: string; link?: string; url?: string };

const isIP = (str: string) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(str);

export default function Home() {
  useEffect(() => { fetch("/track", { method: "POST" }); }, []);

  const [query, setQuery] = useState('');
  const [entryCount, setEntryCount] = useState(0);
  const [entryTypes, setEntryTypes] = useState<{ [key: string]: number }>({});
  const [searchCount, setSearchCount] = useState(0);
  const [cves, setCves] = useState<CVE[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInfo>(null);
  const [geoInfo, setGeoInfo] = useState<GeoInfo>(null);
  const [neutrinoInfo, setNeutrinoInfo] = useState<NeutrinoInfo>(null);
  const [showResult, setShowResult] = useState(false);

  // --- Modern search, using /api/fallback for all enrichment ---
  const handleSearch = async () => {
    if (!query.trim()) return;
    try {
      const resp = await fetch(`/api/fts_search?q=${encodeURIComponent(query)}`);
      const data: ThreatInfo[] = await resp.json();
      let threat: ThreatInfo = null;
      if (Array.isArray(data) && data.length && data[0]?.value) {
        threat = {
          value: data[0].value,
          category: data[0].category,
          source: data[0].source,
          severity: data[0].severity,
          notes: data[0].notes
        };
      } else {
        threat = {
          value: query,
          category: "N/A",
          source: "Fallback",
          severity: "Unknown",
          notes: "Not found in DB"
        };
      }
      setSelectedThreat(threat);
      setShowResult(true);

      const indicatorValue = threat.value?.split(",")[0]?.trim() || threat.value;
      if (isIP(indicatorValue)) {
        const enrichResp = await fetch(`/api/fallback?value=${encodeURIComponent(indicatorValue)}`);
        const enrich = await enrichResp.json();

        if (enrich.geo && enrich.geo.status !== "fail") {
          setGeoInfo({
            ip: enrich.geo.query || threat.value,
            country: enrich.geo.country || "",
            city: enrich.geo.city || "",
            isp: enrich.geo.isp || "",
            lat: enrich.geo.lat,
            lon: enrich.geo.lon,
          });
        } else {
          setGeoInfo(null);
        }

        if (enrich.neutrino) {
          setNeutrinoInfo({
            blocklist: enrich.neutrino.blocklist ?? false,
            reason: enrich.neutrino.reason || enrich.neutrino.message || "N/A",
            country: enrich.neutrino.country || "N/A",
            host: enrich.neutrino.host || "N/A"
          });
        } else {
          setNeutrinoInfo(null);
        }
      } else {
        setGeoInfo(null);
        setNeutrinoInfo(null);
      }

      await fetch('/api/stats/increment-search', { method: 'POST' });
      setSearchCount((prev) => prev + 1);
    } catch (err) {
      console.error(err);
      setError("Failed to fetch search results.");
    }
  };

  const handleBack = () => {
    setShowResult(false);
    setQuery('');
    setSelectedThreat(null);
    setGeoInfo(null);
    setNeutrinoInfo(null);
    setError(null);
  };

  useEffect(() => {
    (async () => {
      try {
        const entries = await fetch("/api/stats/entries").then(r => r.json());
        const searches = await fetch("/api/stats/searches").then(r => r.json());
        const typeBreakdown = await fetch("/api/stats/type-breakdown").then(r => r.json());
        setEntryCount(entries.count);
        setSearchCount(searches.count);
        setEntryTypes(typeBreakdown);
      } catch (err) {
        console.error("Failed to fetch stats:", err);
      }
    })();

    (async () => {
      try {
        const data = await fetch("/api/rss/cves").then(r => r.json());
        setCves(
          data.items.slice(0, 5).map((item: RawCVE) => ({
            title: item.title || item.name || item.cve_id || "Unknown CVE",
            link: item.link || item.url || "#",
          }))
        );
      } catch (err) {
        console.error("Failed to fetch CVEs:", err);
      }
    })();
  }, []);

  // Modal Overlay - No bottom sticky, just one slick panel
  const ResultModal = () => (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-4xl mx-auto rounded-2xl bg-[#191a1f] shadow-2xl flex flex-col md:flex-row overflow-hidden border border-[#23232b]">
        {/* Close (X) Button in Top Right */}
<button
  className="absolute top-4 right-4 text-gray-400 hover:text-red-400 bg-[#23262b] p-2 rounded-full z-10 transition focus:outline-none shadow-md"
  onClick={handleBack}
  title="Close"
>
  <FaTimes className="w-5 h-5" />
</button>

        {/* Info Panel */}
        <div className="flex-1 min-w-[270px] p-8 flex flex-col gap-4 bg-gradient-to-b from-[#23272f]/70 to-[#181a20]/95">
          <h2 className="text-2xl font-bold text-[#7fd1f7] mb-2 flex items-center gap-2">
            <FaShieldAlt /> Indicator Details
          </h2>
          <dl className="grid grid-cols-2 gap-y-3 gap-x-4 text-sm md:text-base">
            <dt className="font-semibold text-[#a3e635]">Indicator</dt>
            <dd className="col-span-1">{selectedThreat?.value}</dd>
            <dt className="font-semibold text-[#a3e635]">Category</dt>
            <dd>{selectedThreat?.category}</dd>
            <dt className="font-semibold text-[#a3e635]">Source</dt>
            <dd>{selectedThreat?.source}</dd>
            <dt className="font-semibold text-[#a3e635]">Severity</dt>
            <dd>{selectedThreat?.severity}</dd>
            <dt className="font-semibold text-[#a3e635]">Notes</dt>
            <dd className="col-span-1">{selectedThreat?.notes}</dd>
            <dt className="font-semibold text-[#a3e635]">Country</dt>
            <dd>{geoInfo?.country || "Unknown"}</dd>
            <dt className="font-semibold text-[#a3e635]">City</dt>
            <dd>{geoInfo?.city || "Unknown"}</dd>
            <dt className="font-semibold text-[#a3e635]">ISP</dt>
            <dd>{geoInfo?.isp || "Unknown"}</dd>
            <dt className="font-semibold text-[#a3e635]">Coordinates</dt>
            <dd>{geoInfo && geoInfo.lat && geoInfo.lon ? `${geoInfo.lat}, ${geoInfo.lon}` : "Unknown"}</dd>
            <dt className="font-semibold text-[#a3e635]">Blocklisted</dt>
            <dd className={neutrinoInfo?.blocklist ? "text-red-400" : "text-green-400"}>
              {neutrinoInfo?.blocklist ? "Yes" : "No"}
            </dd>
            <dt className="font-semibold text-[#a3e635]">Blocklist Reason</dt>
            <dd>{neutrinoInfo?.reason || "N/A"}</dd>
            <dt className="font-semibold text-[#a3e635]">Blocklist Country</dt>
            <dd>{neutrinoInfo?.country || "N/A"}</dd>
            <dt className="font-semibold text-[#a3e635]">Blocklist Host</dt>
            <dd>{neutrinoInfo?.host || "N/A"}</dd>
          </dl>
        </div>
        {/* Map Panel */}
        <div className="flex-1 min-w-[300px] bg-[#21232b] p-8 flex flex-col items-center justify-center border-l border-[#282832]">
          <h4 className="text-lg font-semibold mb-2 text-[#7fd1f7] flex items-center">
            <FaGlobe className="mr-2" /> Location Map
          </h4>
          {geoInfo && geoInfo.lat && geoInfo.lon ? (
            <iframe
              src={`https://www.openstreetmap.org/export/embed.html?bbox=${geoInfo.lon-0.1},${geoInfo.lat-0.1},${geoInfo.lon+0.1},${geoInfo.lat+0.1}&layer=mapnik&marker=${geoInfo.lat},${geoInfo.lon}`}
              className="w-full rounded-xl shadow-xl border border-[#323232] min-h-[200px] max-h-[320px] transition-all"
              loading="lazy"
              allowFullScreen
            />
          ) : (
            <div className="flex items-center justify-center w-full h-[220px] text-gray-500 text-lg bg-[#23262b] rounded-xl">
              No Map Data
            </div>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#181a1f] text-[#e0e0e0] p-6 font-sans">
      <header className="flex items-center mb-8">
        <Image src="/logo.png" alt="Evil-DB Logo" width={48} height={48} className="h-12 mr-4 rounded-xl shadow-md" />
        <h1 className="text-4xl font-extrabold tracking-tight">Evil-DB</h1>
        <a
          href="https://www.buymeacoffee.com/Bmoo"
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto"
        >
          <Image
            src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&amp;emoji=&amp;slug=Bmoo&amp;button_colour=000000&amp;font_colour=ffffff&amp;font_family=Cookie&amp;outline_colour=ffffff&amp;coffee_colour=FFDD00"
            alt="Buy me a coffee"
            width={170}
            height={40}
            className="h-10"
            unoptimized
          />
        </a>
      </header>

      <div className="max-w-2xl mx-auto mb-10">
        <input
          type="text"
          className="w-full p-4 rounded-xl bg-[#222325] border border-[#32333a] focus:outline-none focus:ring-2 focus:ring-[#444] mb-4 shadow-sm"
          placeholder="Search IP, domain, or email..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          disabled={showResult}
        />
        {error && <p className="text-red-500 mb-3 font-medium">{error}</p>}
      </div>

      {/* Main stats page */}
      {!showResult ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-[#23232b] p-5 rounded-xl shadow-md">
            <h2 className="text-xl font-bold mb-3"><FaLock className="inline mr-2 align-text-bottom text-[#7fd1f7]" />Recent CVEs</h2>
            <ul className="list-disc list-inside text-sm space-y-4">
              {cves.map((cve, i) => (
                <li key={i} className="text-[#bbbbbb] leading-snug">
                  <a
                    href={cve.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-blue-400 transition-colors"
                  >
                    {cve.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          <div className="bg-[#23232b] p-5 rounded-xl shadow-md text-center">
            <h2 className="text-xl font-bold mb-2"><FaDatabase className="inline mr-2 align-text-bottom text-[#7fd1f7]" />DB Entries</h2>
            <p className="text-4xl font-mono text-green-400">{entryCount}</p>
            <div className="mt-4 space-y-1 text-sm text-[#cccccc] text-left">
              <p className="font-semibold mb-1">Breakdown by Category:</p>
              {Object.entries(entryTypes).map(([type, count]) => (
                <p key={type}><strong>{type}:</strong> {count}</p>
              ))}
            </div>
          </div>
          <div className="bg-[#23232b] p-5 rounded-xl shadow-md text-center">
            <h2 className="text-xl font-bold mb-2"><FaSearch className="inline mr-2 align-text-bottom text-[#7fd1f7]" />Total Searches</h2>
            <p className="text-4xl font-mono text-yellow-400">{searchCount}</p>
          </div>
        </div>
      ) : (
        // Modal overlay (clean, no sticky bottom)
        <ResultModal />
      )}

      {/* About Section */}
      {!showResult && (
        <section className="mt-20 max-w-3xl mx-auto text-center px-6">
          <h2 className="text-2xl font-bold mb-2 text-[#cccccc]">About Evil-DB</h2>
          <p className="text-[#aaaaaa] text-lg leading-relaxed">
            Evil-DB is an open-source threat intelligence dashboard and indicator search engine.
            Designed for speed, privacy, and a little bit of sass, it lets you quickly check IPs, domains, and emails against a curated database of evil stuff.
            CVEs, GeoIP enrichment, blocklists, you name it. Built with <span className="font-semibold">Next.js</span>, <span className="font-semibold">Tailwind CSS</span>, and enough caffeine to power a small city.
          </p>
          <p className="mt-4 text-[#777] text-sm italic">
            Threat data is for informational use only.
          </p>
          <div className="mt-8 text-left max-w-xl mx-auto">
            <h3 className="text-lg font-bold mb-2 text-[#cccccc]">API Endpoints</h3>
            <ul className="text-[#bbbbbb] text-sm space-y-2 font-mono">
              <li><span className="text-[#7fd1f7]">GET</span> /api/fts_search?q=&lt;value&gt; – Search for threats by IP, domain, or email</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/entries – Total DB entry count</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/type-breakdown – Count by type/category</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/searches – Total search count (because who doesn’t love stats?)</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/rss/cves – Latest CVE news (straight from the abyss)</li>
              <li><span className="text-[#7fd1f7]">POST</span> /api/stats/increment-search – Increment search count (every click counts)</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/check?type=&lt;ip|domain|email&gt;&amp;value=&lt;value&gt; – Check for an exact indicator match</li>
            </ul>
            <p className="text-[#888] mt-2 text-xs">
              For full docs, yell at your nearest developer or just read the damn code. It’s open-source for a reason.
            </p>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="mt-16 pt-10 pb-6 text-center border-t border-[#222226] text-[#666] text-sm">
        <span>
          &copy; {new Date().getFullYear()} Evil-DB &mdash; Made with love and a shit ton of caffeine.<br />
          <span className="text-xs">All trademarks and snarky comments reserved.</span>
        </span>
      </footer>
    </div>
  );
}
