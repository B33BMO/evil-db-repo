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
import { FaLock, FaDatabase, FaSearch, FaArrowLeft, FaGlobe } from 'react-icons/fa';

const isIP = (str) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(str);

export default function Home() {
  useEffect(() => {
    fetch("/track", { method: "POST" });
  }, []);

  const [query, setQuery] = useState('');
  const [entryCount, setEntryCount] = useState(0);
  const [entryTypes, setEntryTypes] = useState({});
  const [searchCount, setSearchCount] = useState(0);
  const [cves, setCves] = useState([]);
  const [error, setError] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [geoInfo, setGeoInfo] = useState(null);
  const [neutrinoInfo, setNeutrinoInfo] = useState(null);
  const [showResult, setShowResult] = useState(false);

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
        setShowResult(true);
        if (isIP(safeArray[0].value)) {
          const ipVal = safeArray[0].value.split('/')[0];
          getGeoInfo(ipVal).then(setGeoInfo).catch(() => setGeoInfo(null));
          getCachedNeutrinoInfo(ipVal).then((info) => setNeutrinoInfo(info)).catch(() => setNeutrinoInfo(null));
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
            setNeutrinoInfo(neut);
          } catch {
            setGeoInfo(null);
            setNeutrinoInfo(null);
          }
        } else {
          setGeoInfo(null);
          setNeutrinoInfo(null);
        }
        setShowResult(true);
      }
      if (isIP(query) && !cachedNeutrino) {
        const live = await getNeutrinoInfo(ipOnly);
        if (live) {
          await saveNeutrinoInfo(ipOnly, live);
        }
      }
      await fetch('/api/stats/increment-search', { method: 'POST' });
      setSearchCount(prev => prev + 1);
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
          data.items.slice(0, 5).map(item => ({
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

  // 🌎 Map placeholder — replace with a real map if you want
  const MapPanel = ({ geo }) =>
    geo && geo.country && geo.city && geo.ip ? (
      <div className="bg-[#222] rounded-xl p-4 shadow-lg h-full flex flex-col justify-between">
        <div>
          <h4 className="text-xl font-semibold mb-2 flex items-center text-[#e0e0e0]"><FaGlobe className="mr-2" />Location Map</h4>
          <p className="text-[#bbbbbb] text-sm mb-2">{geo.city}, {geo.country}</p>
        </div>
        <iframe
          src={`https://www.openstreetmap.org/export/embed.html?bbox=${geo.lon-0.1},${geo.lat-0.1},${geo.lon+0.1},${geo.lat+0.1}&layer=mapnik&marker=${geo.lat},${geo.lon}`}
          className="w-full rounded-xl mt-2"
          style={{ minHeight: '180px', border: 'none' }}
          loading="lazy"
          allowFullScreen
        />
      </div>
    ) : (
      <div className="bg-[#222] rounded-xl p-4 shadow-lg h-full flex items-center justify-center">
        <span className="text-[#888]">No Map Data</span>
      </div>
    );

  // 💻 Detection panel
  const DetectionPanel = ({ threat }) => (
    <div className="bg-[#2b2b2b] p-6 rounded-xl shadow-lg flex flex-col h-full">
      <h4 className="text-xl font-bold mb-2 text-red-400">Detections & Reason</h4>
      <p><strong>Source:</strong> {threat?.source}</p>
      <p><strong>Category:</strong> {threat?.category}</p>
      <p><strong>Severity:</strong> {threat?.severity}</p>
      <p><strong>Notes:</strong> {threat?.notes}</p>
    </div>
  );

  // 👑 Main render
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
          disabled={showResult}
        />
        {error && <p className="text-red-500 mb-3 font-medium">{error}</p>}
      </div>

      {/* Main stats page */}
      {!showResult ? (
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
      ) : (
        // Search result panel/grid
        <div className="w-full">
          <button
            className="flex items-center mb-4 px-4 py-2 bg-[#333] hover:bg-[#444] rounded-lg shadow text-[#ccc] font-bold"
            onClick={handleBack}
          >
            <FaArrowLeft className="mr-2" /> New Search
          </button>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
            {/* Left col: GeoIP & Detections */}
            <div className="flex flex-col gap-6">
              <div className="bg-[#2b2b2b] p-6 rounded-xl shadow-lg flex-1 mb-2">
                <h3 className="text-xl font-bold mb-2 text-[#7fd1f7]">GeoIP & IP Info</h3>
                {geoInfo ? (
                  <>
                    <p><strong>IP:</strong> {geoInfo.ip}</p>
                    <p><strong>Country:</strong> {geoInfo.country}</p>
                    <p><strong>City:</strong> {geoInfo.city}</p>
                    <p><strong>ISP:</strong> {geoInfo.isp}</p>
                  </>
                ) : (
                  <p className="text-red-400">No GeoIP info.</p>
                )}
              </div>
              <DetectionPanel threat={selectedThreat} />
            </div>
            {/* Middle col: Neutrino API */}
            <div className="bg-[#2b2b2b] p-6 rounded-xl shadow-lg flex flex-col h-full">
              <h3 className="text-xl font-bold mb-2 text-[#7fd1f7]">Neutrino API</h3>
              {neutrinoInfo ? (
                <>
                  <p><strong>Blocklisted:</strong> {neutrinoInfo.blocklist ? 'Yes' : 'No'}</p>
                  <p><strong>Reason:</strong> {neutrinoInfo.reason || 'N/A'}</p>
                  <p><strong>Country:</strong> {neutrinoInfo.country || 'N/A'}</p>
                  <p><strong>Host:</strong> {neutrinoInfo.host || 'N/A'}</p>
                </>
              ) : (
                <p className="text-red-400">Can't load Neutrino info.</p>
              )}
            </div>
            {/* Right col: Map */}
            <MapPanel geo={geoInfo && geoInfo.lat && geoInfo.lon ? geoInfo : null} />
          </div>
        </div>
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
              <li><span className="text-[#7fd1f7]">GET</span> /api/search?q=&lt;value&gt; – Search for threats by IP, domain, or email</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/entries – Total DB entry count</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/type-breakdown – Count by type/category</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/stats/searches – Total search count (because who doesn’t love stats?)</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/rss/cves – Latest CVE news (straight from the abyss)</li>
              <li><span className="text-[#7fd1f7]">POST</span> /api/stats/increment-search – Increment search count (every click counts)</li>
              <li><span className="text-[#7fd1f7]">GET</span> /api/check?type=&lt;ip|domain|email&gt;&value=&lt;value&gt; – Check for an exact indicator match</li>
            </ul>
            <p className="text-[#888] mt-2 text-xs">
              For full docs, yell at your nearest developer or just read the damn code. It’s open-source for a reason.
            </p>
          </div>
        </section>
      )}

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
