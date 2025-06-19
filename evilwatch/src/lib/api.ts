// /lib/api.ts

export interface ThreatInfo {
  // Define properties based on expected threat search result structure
  [key: string]: unknown;
}

export interface EntryCount {
  count: number;
}

export interface SearchCount {
  count: number;
}

export interface CveItem {
  // Define properties for a single CVE item
  [key: string]: unknown;
}

export interface CveFeed {
  items: CveItem[];
}

export interface GeoInfo {
  ip: string;
  country: string;
  city: string;
  isp: string;
}

export interface NeutrinoInfo {
  // Define properties based on Neutrino API response structure
  [key: string]: unknown;
}

export interface EntryTypeBreakdown {
  [key: string]: number;
}

export async function searchThreat(q: string): Promise<ThreatInfo> {
  // Fetch threat information based on query string
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  if (!res.ok) throw new Error("Failed to search");
  return res.json();
}

export async function getEntryCount(): Promise<EntryCount> {
  // Fetch total entry count statistics
  const res = await fetch(`/api/stats/entries`);
  return res.ok ? res.json() : { count: 0 };
}

export async function getSearchCount(): Promise<SearchCount> {
  // Fetch total search count statistics
  const res = await fetch(`/api/stats/searches`);
  return res.ok ? res.json() : { count: 0 };
}

export async function getCVEs(): Promise<CveFeed> {
  // Fetch CVE RSS feed items
  const res = await fetch(`/api/rss/cves`);
  return res.ok ? res.json() : { items: [] };
}

export async function getGeoInfo(ip: string): Promise<GeoInfo | null> {
  // Fetch geographic information for an IP address
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}`);
    if (!res.ok) throw new Error("GeoIP lookup failed");
    const data = await res.json();
    return {
      ip: data.query,
      country: data.country,
      city: data.city,
      isp: data.isp,
    };
  } catch (err) {
    // Log error and return null on failure
    console.error("GeoIP Error:", err);
    return null;
  }
}

export async function getNeutrinoInfo(ip: string): Promise<NeutrinoInfo | null> {
  // Fetch live Neutrino API information for an IP address
  try {
    const res = await fetch(`/api/neutrino/live?ip=${ip}`);
    if (!res.ok) throw new Error("Neutrino lookup failed");
    return res.json();
  } catch (err) {
    // Log error and return null on failure
    console.error("Neutrino API Error:", err);
    return null;
  }
}

export async function getCachedNeutrinoInfo(ip: string): Promise<NeutrinoInfo | null> {
  // Fetch cached Neutrino API information for an IP address
  try {
    const res = await fetch(`/api/neutrino/cache?ip=${ip}`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    // Return null if any error occurs
    return null;
  }
}

export async function saveNeutrinoInfo(ip: string, data: NeutrinoInfo): Promise<boolean> {
  // Save Neutrino API information for an IP address
  try {
    const res = await fetch(`/api/neutrino/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, data }),
    });
    return res.ok;
  } catch (err) {
    // Log error and return false on failure
    console.error("Failed to save Neutrino info:", err);
    return false;
  }
}

export async function incrementSearchCount(): Promise<boolean> {
  // Increment the search count statistic
  try {
    const res = await fetch(`/api/stats/increment-search`, { method: 'POST' });
    return res.ok;
  } catch (err) {
    // Log error and return false on failure
    console.error("Search increment failed:", err);
    return false;
  }
}

export async function getEntryTypeBreakdown(): Promise<EntryTypeBreakdown> {
  // Fetch breakdown of entry types
  const res = await fetch("/api/stats/type-breakdown");
  if (!res.ok) return {};
  return res.json();
}