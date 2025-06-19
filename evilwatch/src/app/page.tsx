// Show "No match found" only after searching!
"use client";
import Image from "next/image";
import { useState, useEffect } from 'react';
import {
  searchThreat,
  getEntryCount,
  getSearchCount,
  getCVEs,
  getGeoInfo,
  getNeutrinoInfo,
  saveNeutrinoInfo,
  getCachedNeutrinoInfo,
  getEntryTypeBreakdown
} from "@/lib/api";
import { FaLock, FaDatabase, FaSearch } from 'react-icons/fa';
const isIP = (str: string) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(str);
type GeoInfo = {
  ip: string;
  country: string;
  city: string;
  isp: string;
} | null;

type ThreatInfo = {
  value: string;
  category: string;
  source: string;
  severity: string;
  notes: string;
} | null;

type NeutrinoInfo = {
  blocklist: boolean;
  reason: string;
  country: string;
  host: string;
} | null;

export default function Home() {
  const [query, setQuery] = useState<string>('');
  const [entryCount, setEntryCount] = useState<number>(0);
  const [entryTypes, setEntryTypes] = useState<{ [key: string]: number }>({});
  const [searchCount, setSearchCount] = useState<number>(0);
  const [cves, setCves] = useState<{ title: string; link: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInfo | null>(null);
  const [geoInfo, setGeoInfo] = useState<GeoInfo>(null);
  const [neutrinoInfo, setNeutrinoInfo] = useState<NeutrinoInfo>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    try {
      const ipOnly = query.split('/')[0];
      const [data, , cachedNeutrino] = await Promise.all([
        searchThreat(query),
        isIP(query) ? getGeoInfo(ipOnly) : Promise.resolve(null),
        isIP(query) ? getCachedNeutrinoInfo(ipOnly) : Promise.resolve(null)
      ]);

      const safeArray = Array.isArray(data) ? data : data ? [data] : [];

      if (safeArray.length > 0) {
        setSelectedThreat(safeArray[0]);
        setModalOpen(true);
        if (isIP(safeArray[0].value)) {
          const ipVal = safeArray[0].value.split('/')[0];
          getGeoInfo(ipVal).then(setGeoInfo).catch(() => setGeoInfo(null));
          getCachedNeutrinoInfo(ipVal).then((info) => setNeutrinoInfo(info as NeutrinoInfo)).catch(() => setNeutrinoInfo(null));
        } else {
          setGeoInfo(null);
          setNeutrinoInfo(null);
        }
      } else {
        const fallback = {
          value: query,
          category: "N/A",
          source: "Fallback",
          severity: "Unknown",
          notes: "Not found in DB"
        };
        setSelectedThreat(fallback);

        if (isIP(query)) {
          const ipVal = query.split('/')[0];
          try {
            const geo = await getGeoInfo(ipVal);
            const neut = await getCachedNeutrinoInfo(ipVal);
            setGeoInfo(geo);
            setNeutrinoInfo(neut as NeutrinoInfo);
          } catch {
            setGeoInfo(null);
            setNeutrinoInfo(null);
          }
        } else {
          setGeoInfo(null);
          setNeutrinoInfo(null);
        }

        setModalOpen(true);
      }

      if (isIP(query)) {
        if (cachedNeutrino) {
        } else {
          const live = await getNeutrinoInfo(ipOnly);
          if (live) {
            await saveNeutrinoInfo(ipOnly, live);
          }
        }
      }

      await fetch('/api/stats/increment-search', { method: 'POST' });
      setSearchCount(prev => prev + 1);
    } catch (err) {
      console.error(err);
      setError("Failed to fetch search results.");
    }
  };

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [entries, searches, typeBreakdown] = await Promise.all([
          getEntryCount(),
          getSearchCount(),
          getEntryTypeBreakdown()
        ]);
        setEntryCount(entries.count);
        setSearchCount(searches.count);
        setEntryTypes(typeBreakdown);
      } catch (err) {
        console.error("Failed to fetch stats:", err);
      }
    };

    const fetchCVEs = async () => {
      try {
        const data = await getCVEs();
        setCves(
          data.items.slice(0, 5).map((item: { title?: string; name?: string; cve_id?: string; link?: string; url?: string }) => ({
            title: item.title || item.name || item.cve_id || "Unknown CVE",
            link: item.link || item.url || "#",
          }))
        );
      } catch (err) {
        console.error("Failed to fetch CVEs:", err);
      }
    };

    fetchStats();
    fetchCVEs();
  }, []);

  return (
    <div className="min-h-screen bg-[#1e1e1e] text-[#e0e0e0] p-6 font-sans">
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
          className="w-full p-4 rounded-xl bg-[#333333] border border-[#3d3d3d] focus:outline-none focus:ring-2 focus:ring-[#555] mb-4 shadow-sm"
          placeholder="Search IP, domain, or email..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
        />
        {error && <p className="text-red-500 mb-3 font-medium">{error}</p>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#2b2b2b] p-5 rounded-xl shadow-md">
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
        <div className="bg-[#2b2b2b] p-5 rounded-xl shadow-md text-center">
          <h2 className="text-xl font-bold mb-2"><FaDatabase className="inline mr-2 align-text-bottom text-[#7fd1f7]" />DB Entries</h2>
          <p className="text-4xl font-mono text-green-400">{entryCount}</p>
          <div className="mt-4 space-y-1 text-sm text-[#cccccc] text-left">
            <p className="font-semibold mb-1">Breakdown by Category:</p>
            {Object.entries(entryTypes).map(([type, count]) => (
              <p key={type}><strong>{type}:</strong> {count}</p>
            ))}
          </div>
        </div>
        <div className="bg-[#2b2b2b] p-5 rounded-xl shadow-md text-center">
          <h2 className="text-xl font-bold mb-2"><FaSearch className="inline mr-2 align-text-bottom text-[#7fd1f7]" />Total Searches</h2>
          <p className="text-4xl font-mono text-yellow-400">{searchCount}</p>
        </div>
      </div>

      {modalOpen && selectedThreat && (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex justify-center items-center z-50">
          <div className="bg-[#2b2b2b] text-[#e0e0e0] p-8 rounded-2xl shadow-2xl w-full max-w-6xl border border-[#3d3d3d]">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-3xl font-bold text-[#cccccc]">Threat Intelligence Report</h3>
              <button
                className="text-[#cccccc] hover:text-red-400 text-xl"
                onClick={() => setModalOpen(false)}
              >
                ✖
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-[#333333] rounded-lg p-4 shadow">
                <h4 className="text-xl font-semibold mb-2 text-[#e0e0e0]">🧠 Threat Details</h4>
                <p><strong>Value:</strong> {selectedThreat.value}</p>
                <p><strong>Category:</strong> {selectedThreat.category}</p>
                <p><strong>Source:</strong> {selectedThreat.source}</p>
                <p><strong>Severity:</strong> {selectedThreat.severity}</p>
                <p><strong>Notes:</strong> {selectedThreat.notes}</p>
              </div>
              {geoInfo && (
                <div className="bg-[#333333] rounded-lg p-4 shadow">
                  <h4 className="text-xl font-semibold mb-2 text-[#e0e0e0]">🌍 GeoIP Info</h4>
                  <p><strong>IP:</strong> {geoInfo.ip}</p>
                  <p><strong>Country:</strong> {geoInfo.country}</p>
                  <p><strong>City:</strong> {geoInfo.city}</p>
                  <p><strong>ISP:</strong> {geoInfo.isp}</p>
                </div>
              )}
              {neutrinoInfo && (
                <div className="bg-[#333333] rounded-lg p-4 shadow md:col-span-2">
                  <h4 className="text-xl font-semibold mb-2 text-[#e0e0e0]">🧪 Enrichment Report</h4>
                  <p><strong>Source:</strong> {(neutrinoInfo as any).source_used || 'Neutrino'}</p>
                  <p><strong>Blocklisted:</strong> {neutrinoInfo.blocklist ? 'Yes' : 'No'}</p>
                  <p><strong>Reason:</strong> {neutrinoInfo.reason}</p>
                  <p><strong>Country:</strong> {neutrinoInfo.country}</p>
                  <p><strong>Host:</strong> {neutrinoInfo.host}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* About Section */}
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
            <li><span className="text-[#7fd1f7]">GET</span> /api/search?q=<i>value</i> – Search for threats by IP, domain, or email</li>
            <li><span className="text-[#7fd1f7]">GET</span> /api/stats/entries – Total DB entry count</li>
            <li><span className="text-[#7fd1f7]">GET</span> /api/stats/type-breakdown – Count by type/category</li>
            <li><span className="text-[#7fd1f7]">GET</span> /api/stats/searches – Total search count (because who doesn&rsquo;t love stats?)</li>
            <li><span className="text-[#7fd1f7]">GET</span> /api/rss/cves – Latest CVE news (straight from the abyss)</li>
            <li><span className="text-[#7fd1f7]">POST</span> /api/stats/increment-search – Increment search count (every click counts)</li>
            <li><span className="text-[#7fd1f7]">GET</span> /api/check?type=<i>ip|domain|email</i>&value=<i>value</i> – Check for an exact indicator match</li>
          </ul>
          <p className="text-[#888] mt-2 text-xs">
            For full docs, yell at your nearest developer or just read the damn code. It’s open-source for a reason.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-16 pt-10 pb-6 text-center border-t border-[#292929] text-[#666] text-sm">
        <span>
          &copy; {new Date().getFullYear()} Evil-DB &mdash; Made with bad intentions, good code.<br />
          <span className="text-xs">All trademarks and snarky comments reserved.</span>
        </span>
      </footer>
    </div>
  );
}