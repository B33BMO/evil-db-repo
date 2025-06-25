"use client";
import Image from "next/image";
import { useState, useEffect } from 'react';
import { FaLock, FaDatabase, FaSearch, FaArrowLeft } from 'react-icons/fa';

type ThreatInfo = {
  value: string;
  category: string;
  source: string;
  severity: string;
  notes: string;
} | null;

type CVE = { title: string; link: string; };
type RawCVE = { title?: string; name?: string; cve_id?: string; link?: string; url?: string };

export default function Home() {
  useEffect(() => { fetch("/track", { method: "POST" }); }, []);

  const [query, setQuery] = useState('');
  const [entryCount, setEntryCount] = useState(0);
  const [entryTypes, setEntryTypes] = useState<{ [key: string]: number }>({});
  const [searchCount, setSearchCount] = useState(0);
  const [cves, setCves] = useState<CVE[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInfo>(null);
  const [showResult, setShowResult] = useState(false);

  // -- Search only the DB --
  const handleSearch = async () => {
    if (!query.trim()) return;
    try {
      const resp = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
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
          source: "DB",
          severity: "Unknown",
          notes: "Not found in DB"
        };
      }
      setSelectedThreat(threat);
      setShowResult(true);

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

  // No geo panel, no Neutrino. Just detection panel.
  const DetectionPanel = ({ threat }: { threat: ThreatInfo }) => (
    <div className="bg-[#2b2b2b] p-6 rounded-xl shadow-lg flex flex-col h-full">
      <h4 className="text-xl font-bold mb-2 text-red-400">Detection Result</h4>
      <p><strong>Source:</strong> {threat?.source}</p>
      <p><strong>Category:</strong> {threat?.category}</p>
      <p><strong>Severity:</strong> {threat?.severity}</p>
      <p><strong>Notes:</strong> {threat?.notes}</p>
    </div>
  );

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
        // Show result panel
        <div className="w-full">
          <button
            className="flex items-center mb-4 px-4 py-2 bg-[#333] hover:bg-[#444] rounded-lg shadow text-[#ccc] font-bold"
            onClick={handleBack}
          >
            <FaArrowLeft className="mr-2" /> New Search
          </button>
          <DetectionPanel threat={selectedThreat} />
        </div>
      )}

      {/* About Section */}
      {!showResult && (
        <section className="mt-20 max-w-3xl mx-auto text-center px-6">
          <h2 className="text-2xl font-bold mb-2 text-[#cccccc]">About Evil-DB</h2>
          <p className="text-[#aaaaaa] text-lg leading-relaxed">
            Evil-DB is an open-source threat intelligence dashboard and indicator search engine.
            Designed for speed, privacy, and a little bit of sass, it lets you quickly check IPs, domains, and emails against a curated database of evil stuff.
            CVEs, blocklists, you name it. Built with <span className="font-semibold">Next.js</span>, <span className="font-semibold">Tailwind CSS</span>, and enough caffeine to power a small city.
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
              <li><span className="text-[#7fd1f7]">GET</span> /api/check?type=&lt;ip|domain|email&gt;&amp;value=&lt;value&gt; – Check for an exact indicator match</li>
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
          &copy; {new Date().getFullYear()} Evil-DB &mdash; Made with love and a shit ton of caffeine.<br />
          <span className="text-xs">All trademarks and snarky comments reserved.</span>
        </span>
      </footer>
    </div>
  );
}
