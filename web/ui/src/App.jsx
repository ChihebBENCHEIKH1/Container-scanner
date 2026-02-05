import React, { useState, useEffect } from 'react';
import { Shield, Search, Play, CheckCircle, AlertTriangle, ShieldAlert, Info, List, Server, Activity, ArrowRight } from 'lucide-react';
import './App.css';

function App() {
  const [images, setImages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [selectedImage, setSelectedImage] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchImages();
  }, []);

  const fetchImages = async () => {
    try {
      const resp = await fetch('/api/images');
      const data = await resp.json();
      setImages(data || []);
      setLoading(false);
    } catch (err) {
      console.error('Error fetching images:', err);
      setLoading(false);
    }
  };

  const runScan = async () => {
    if (!selectedImage) return;
    setScanning(true);
    setScanResult(null);
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageName: selectedImage })
      });
      const data = await resp.json();
      setScanResult(data);
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setScanning(false);
    }
  };

  const filteredImages = images.filter(img => 
    img.RepoTags && img.RepoTags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="app-container">
      <header className="animate-fade-in" style={{ marginBottom: '3rem', textAlign: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ padding: '0.8rem', background: 'linear-gradient(135deg, #7928ca, #ff0080)', borderRadius: '12px' }}>
            <Shield size={32} color="white" />
          </div>
          <h1 style={{ fontSize: '2.5rem', fontWeight: 800 }}>Guard<span style={{ color: 'var(--primary-color)' }}>Container</span></h1>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '1.1rem' }}>Advanced Security Orchestration for Docker Environments</p>
      </header>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '2rem' }}>
        {/* Left Panel: Image Selection */}
        <section className="glass-card animate-fade-in" style={{ height: 'fit-content' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
            <Server size={20} color="var(--primary-color)" />
            <h2 style={{ fontSize: '1.25rem' }}>Local Images</h2>
          </div>

          <div style={{ position: 'relative', marginBottom: '1.5rem' }}>
            <Search size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input 
              className="input-field" 
              placeholder="Search images..." 
              style={{ paddingLeft: '40px' }}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="image-list" style={{ maxHeight: '400px', overflowY: 'auto', marginBottom: '1.5rem' }}>
            {loading ? (
              <p style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading images...</p>
            ) : filteredImages.length === 0 ? (
              <p style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No images found.</p>
            ) : (
              filteredImages.map((img) => (
                <div 
                  key={img.Id} 
                  className={`image-item ${selectedImage === img.RepoTags[0] ? 'selected' : ''}`}
                  onClick={() => setSelectedImage(img.RepoTags[0])}
                >
                  <p className="repo-tag">{img.RepoTags[0]}</p>
                  <p className="image-id">{img.Id.substring(7, 19)}</p>
                </div>
              ))
            )}
          </div>

          <button 
            className="btn" 
            style={{ width: '100%' }} 
            onClick={runScan}
            disabled={!selectedImage || scanning}
          >
            {scanning ? <Activity className="animate-spin" size={20} /> : <Play size={20} />}
            {scanning ? 'Scanning...' : 'Start Analysis'}
          </button>
        </section>

        {/* Right Panel: Results */}
        <section className="glass-card animate-fade-in" style={{ minHeight: '600px' }}>
          {!scanResult && !scanning ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-secondary)', padding: '2rem', textAlign: 'center' }}>
              <Shield size={64} opacity={0.1} style={{ marginBottom: '1.5rem' }} />
              <h3>Ready to Scan</h3>
              <p>Select an image from the sidebar to begin security analysis.</p>
            </div>
          ) : scanning ? (
             <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '2rem', textAlign: 'center' }}>
              <div className="scanning-pulse" style={{ marginBottom: '2rem' }}>
                 <Activity size={48} color="var(--primary-color)" />
              </div>
              <h3>Analyzing {selectedImage}</h3>
              <p style={{ color: 'var(--text-secondary)' }}>Extracting filesystem and probing endpoints...</p>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>Security Report</h2>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Image: {selectedImage}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                   <div className="badge badge-info" style={{ marginBottom: '0.5rem', display: 'inline-block' }}>
                    {scanResult.findings.length} Issues Found
                   </div>
                   <p style={{ fontSize: '0.75rem', opacity: 0.5 }}>Scan completed in 1.2s</p>
                </div>
              </div>

              <div className="findings-container">
                {scanResult.findings.length === 0 ? (
                  <div className="glass-card" style={{ background: 'rgba(63, 185, 80, 0.05)', borderColor: 'rgba(63, 185, 80, 0.2)', textAlign: 'center' }}>
                     <CheckCircle size={32} color="var(--success-color)" style={{ marginBottom: '1rem' }} />
                     <h3 style={{ color: 'var(--success-color)' }}>No Vulnerabilities Found</h3>
                     <p style={{ color: 'var(--text-secondary)' }}>This image passed all security orchestration checks.</p>
                  </div>
                ) : (
                  scanResult.findings.map((f, i) => (
                    <div key={i} className="finding-item glass-card animate-fade-in" style={{ animationDelay: `${i * 0.1}s`, marginBottom: '1rem', background: 'rgba(255, 255, 255, 0.02)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                           {getSeverityIcon(f.severity)}
                           <div>
                              <h4 style={{ fontSize: '1rem' }}>{f.description}</h4>
                              <p style={{ fontSize: '0.8rem', opacity: 0.6 }}>{f.scanner}</p>
                           </div>
                        </div>
                        <span className={`badge badge-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
                      </div>
                      <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{f.details}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

const getSeverityIcon = (severity) => {
  if (!severity) return <Info color="#3fb950" size={20} />;
  switch (severity.toUpperCase()) {
    case 'HIGH': return <ShieldAlert color="#f85149" size={20} />;
    case 'MEDIUM': return <AlertTriangle color="#d29922" size={20} />;
    default: return <Info color="#3fb950" size={20} />;
  }
};

export default App;
