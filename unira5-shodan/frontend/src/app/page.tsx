'use client';

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import dynamic from 'next/dynamic';
import { Search, Globe, Shield, Activity, Lock } from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8759/api';

// Dynamically import map component
const Map = dynamic(() => import('./components/Map'), {
  ssr: false,
  loading: () => <div className="text-green-500 animate-pulse text-center p-12">Loading Global Map Module...</div>
});

export default function Home() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Mock WebSocket for demo
    // In production, use real WS:
    // const ws = new WebSocket('ws://' + window.location.host + '/api/ws');
    // ws.onmessage = (event) => setLiveLog((prev) => [event.data, ...prev].slice(0, 50));
    // return () => ws.close();
    setLiveLog(["System Initialized. Awaiting Instructions."]);
  }, []);

  const handleSearch = async () => {
    setLoading(true);
    try {
      // In real scenario, scan or search based on query format
      if (query.includes(':') || query.includes(' ')) {
        // Search
        setLiveLog((prev) => [`Executing search query: ${query}...`, ...prev]);
        const res = await axios.get(`${API_URL}/search?q=${query}`);
        setResults(res.data);
      } else {
        // Trigger Scan
        setLiveLog((prev) => [`Initiating scan for target: ${query}...`, ...prev]);
        await axios.post(`${API_URL}/scan`, { target: query });
        setLiveLog((prev) => [`Scan task dispatched for ${query}.`, ...prev]);
      }
    } catch (e: any) {
      console.error(e);
      setLiveLog((prev) => [`ERROR: ${e.message}`, ...prev]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center bg-black text-green-500 font-mono p-4">
      <header className="w-full flex justify-between items-center p-6 border-b border-green-900/30">
        <h1 className="text-4xl font-bold tracking-tighter glow">UNIRA5-SHODAN</h1>
        <div className="flex gap-4">
          <Shield className="w-6 h-6 animate-pulse" />
          <Activity className="w-6 h-6" />
        </div>
      </header>

      <section className="w-full max-w-5xl mt-12 flex flex-col gap-8">
        {/* Search Bar */}
        <div className="relative group">
          <input
            type="text"
            placeholder="Enter IP, CIDR, or Query (e.g. port:80)..."
            className="w-full bg-gray-900/50 border border-green-700/50 rounded-lg p-4 pl-12 text-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 transition-all"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          />
          <Search className="absolute left-4 top-4 text-green-700" />
          <button
            onClick={handleSearch}
            disabled={loading}
            className="absolute right-2 top-2 bg-green-900/80 hover:bg-green-700 text-white px-6 py-2 rounded transition-colors"
          >
            {loading ? 'PROCESSING...' : 'EXECUTE'}
          </button>
        </div>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Live Feed */}
          <div className="bg-gray-900/30 border border-green-800/30 p-4 rounded-lg h-96 overflow-hidden flex flex-col">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Live Operations
            </h2>
            <div className="flex-1 overflow-y-auto space-y-2 font-mono text-sm scrollbar-thin scrollbar-thumb-green-900 scrollbar-track-black">
              {liveLog.map((log, i) => (
                <div key={i} className="border-l-2 border-green-500/50 pl-2 py-1 bg-black/40">
                  <span className="text-green-300">[{new Date().toLocaleTimeString()}]</span> {log}
                </div>
              ))}
            </div>
          </div>

          {/* Map Module */}
          <div className="bg-gray-900/30 border border-green-800/30 p-4 rounded-lg h-96 relative overflow-hidden flex flex-col">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4" /> Global Threat Map
            </h2>
            <div className="flex-1 relative w-full h-full rounded border border-green-900/20 overflow-hidden">
               <Map data={results} />
            </div>
          </div>
        </div>

        {/* Results Table */}
        {results.length > 0 && (
          <div className="bg-gray-900/30 border border-green-800/30 p-6 rounded-lg mb-12">
            <h2 className="text-2xl font-bold mb-6">Discovery Results ({results.length})</h2>
            <div className="space-y-4">
              {results.map((res: any, idx) => (
                <div key={idx} className="border border-green-900/50 p-4 rounded bg-black/60 hover:bg-green-900/10 transition-colors group">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-xl font-bold text-white group-hover:text-green-400 transition-colors">{res._source.target}</h3>
                      <p className="text-sm text-gray-400 font-mono mt-1">
                        {res._source.geoip?.city}, {res._source.geoip?.country} ({res._source.geoip?.org})
                      </p>
                      <div className="flex flex-wrap gap-2 mt-2">
                         {res._source.ports?.map((p: string) => (
                           <span key={p} className="bg-green-900/20 text-green-300 px-2 py-0.5 rounded text-xs border border-green-800/50">{p}</span>
                         ))}
                      </div>
                    </div>
                    <div className="flex flex-col gap-2 items-end">
                      <span className="text-xs text-gray-600">{new Date(res._source.timestamp).toLocaleString()}</span>
                      {res._source.vulns?.length > 0 && (
                        <span className="bg-red-900/50 text-red-200 px-2 py-1 rounded text-xs border border-red-800 animate-pulse">VULN DETECTED</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
