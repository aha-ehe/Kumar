"use client";

import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import 'leaflet/dist/leaflet.css';

// Dynamic import for Leaflet to avoid SSR issues
const MapContainer = dynamic(
  () => import('react-leaflet').then((mod) => mod.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import('react-leaflet').then((mod) => mod.TileLayer),
  { ssr: false }
);
const Marker = dynamic(
  () => import('react-leaflet').then((mod) => mod.Marker),
  { ssr: false }
);
const Popup = dynamic(
  () => import('react-leaflet').then((mod) => mod.Popup),
  { ssr: false }
);

export default function Map({ data }: { data: any[] }) {
  const [L, setL] = useState<any>(null);

  useEffect(() => {
    import('leaflet').then((mod) => {
      setL(mod.default);
      // Fix marker icon issue in Next.js
      delete (mod.default.Icon.Default.prototype as any)._getIconUrl;
      mod.default.Icon.Default.mergeOptions({
        iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
        iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
        shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
      });
    });
  }, []);

  if (!L || typeof window === 'undefined') {
    return <div className="w-full h-full flex items-center justify-center text-green-900 animate-pulse">Initializing Global Map...</div>;
  }

  return (
    <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={false} className="w-full h-full rounded-lg z-0">
      <TileLayer
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />
      {data.map((point, idx) => {
        const lat = point._source.geoip?.latitude;
        const lng = point._source.geoip?.longitude;
        if (lat && lng) {
          return (
            <Marker key={idx} position={[lat, lng]}>
              <Popup>
                <div className="text-black">
                  <strong>{point._source.target}</strong><br/>
                  {point._source.geoip?.city}, {point._source.geoip?.country}<br/>
                  Ports: {point._source.ports?.join(', ')}
                </div>
              </Popup>
            </Marker>
          );
        }
        return null;
      })}
    </MapContainer>
  );
}
