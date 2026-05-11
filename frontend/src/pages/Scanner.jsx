import { useState, useRef, useCallback, useEffect } from 'react'
import { checkUrl, checkQrCode } from '../api'
import ThreatGauge from '../components/ThreatGauge'
import jsQR from 'jsqr'

function Scanner() {
  const [activeTab, setActiveTab] = useState('url')  // 'url' | 'qr'
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [qrPreview, setQrPreview] = useState(null)
  const [cameraActive, setCameraActive] = useState(false)

  const fileInputRef = useRef(null)
  const videoRef = useRef(null)
  const canvasRef = useRef(null)
  const streamRef = useRef(null)
  const animFrameRef = useRef(null)

  // Cleanup camera on unmount
  useEffect(() => {
    return () => {
      stopCamera()
    }
  }, [])

  const handleScan = async (e) => {
    e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await checkUrl(url.trim())
      setResult(data)
    } catch (err) {
      setError('Failed to scan URL. Make sure the API server is running.')
    } finally {
      setLoading(false)
    }
  }

  // ---- QR Code Handlers ----

  const handleQrFile = async (file) => {
    if (!file || !file.type.startsWith('image/')) {
      setError('Please upload a valid image file')
      return
    }

    // Show preview
    const reader = new FileReader()
    reader.onload = async (e) => {
      setQrPreview(e.target.result)
      
      // Decode QR code client-side using jsQR
      const img = new Image()
      img.onload = async () => {
        const canvas = document.createElement('canvas')
        canvas.width = img.width
        canvas.height = img.height
        const ctx = canvas.getContext('2d')
        ctx.drawImage(img, 0, 0)
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
        const code = jsQR(imageData.data, imageData.width, imageData.height)

        if (!code) {
          setError('No QR code detected in the image. Please try a clearer image.')
          setLoading(false)
          return
        }

        const decodedUrl = code.data
        setUrl(decodedUrl)

        try {
          const data = await checkQrCode(decodedUrl)
          if (data.error) {
            setError(data.error)
          } else {
            setResult(data)
          }
        } catch (err) {
          setError('Failed to analyze QR code URL. Make sure the API server is running.')
        } finally {
          setLoading(false)
        }
      }
      img.src = e.target.result
    }

    setLoading(true)
    setError(null)
    setResult(null)
    reader.readAsDataURL(file)
  }

  const handleFileInput = (e) => {
    const file = e.target.files?.[0]
    if (file) handleQrFile(file)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleQrFile(file)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    setDragOver(true)
  }

  const handleDragLeave = () => setDragOver(false)

  // ---- Camera QR Scanning ----

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: 640, height: 480 }
      })
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        videoRef.current.play()
      }
      setCameraActive(true)
      scanFrame()
    } catch (err) {
      setError('Camera access denied. Please allow camera permissions.')
    }
  }

  const stopCamera = () => {
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current)
      animFrameRef.current = null
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop())
      streamRef.current = null
    }
    setCameraActive(false)
  }

  const scanFrame = useCallback(() => {
    const video = videoRef.current
    const canvas = canvasRef.current
    if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
      animFrameRef.current = requestAnimationFrame(scanFrame)
      return
    }

    const ctx = canvas.getContext('2d')
    canvas.width = video.videoWidth
    canvas.height = video.videoHeight
    ctx.drawImage(video, 0, 0)
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
    const code = jsQR(imageData.data, imageData.width, imageData.height)

    if (code) {
      // Found QR code
      stopCamera()
      setUrl(code.data)
      // Auto-scan the decoded URL
      setLoading(true)
      setError(null)
      setResult(null)
      checkQrCode(code.data)
        .then(data => setResult(data))
        .catch(() => setError('Failed to scan decoded URL'))
        .finally(() => setLoading(false))
      return
    }

    animFrameRef.current = requestAnimationFrame(scanFrame)
  }, [])

  const getLabelIcon = (label) => {
    switch (label) {
      case 'SAFE': return '✅'
      case 'WARN': return '⚠️'
      case 'BLOCK': return '🚫'
      default: return '❓'
    }
  }

  const getDirectionIcon = (direction) => {
    return direction === 'risk' ? '🔴' : '🟢'
  }

  const getNlpRiskColor = (score) => {
    if (score <= 15) return 'var(--safe)'
    if (score <= 40) return 'var(--warn)'
    return 'var(--block)'
  }

  return (
    <div className="page scanner-page">
      <div className="page-header">
        <h1>Threat Scanner</h1>
        <p>Analyze URLs and QR codes for phishing, scams, and malicious content using AI</p>
      </div>

      {/* Tab Switcher */}
      <div className="scanner-tabs">
        <button
          className={`scanner-tab ${activeTab === 'url' ? 'active' : ''}`}
          onClick={() => { setActiveTab('url'); stopCamera() }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
          </svg>
          URL Input
        </button>
        <button
          className={`scanner-tab ${activeTab === 'qr' ? 'active' : ''}`}
          onClick={() => setActiveTab('qr')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/>
            <rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="2" height="2"/>
            <rect x="20" y="16" width="2" height="2"/><rect x="16" y="20" width="2" height="2"/>
            <rect x="20" y="20" width="2" height="2"/><rect x="18" y="18" width="2" height="2"/>
            <path d="M12 2v4"/><path d="M12 8v2"/><path d="M2 12h4"/><path d="M8 12h2"/>
            <path d="M12 12h10"/><path d="M12 12v10"/>
          </svg>
          QR Code Scan
        </button>
      </div>

      {/* URL Input Tab */}
      {activeTab === 'url' && (
        <form className="scanner-form" onSubmit={handleScan}>
          <div className="input-group">
            <div className="input-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
              </svg>
            </div>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (e.g., https://example.com)"
              autoComplete="off"
            />
            <button
              id="scan-button"
              type="submit"
              className={`scan-btn ${loading ? 'scanning' : ''}`}
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Scanning...
                </>
              ) : (
                <>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  Scan URL
                </>
              )}
            </button>
          </div>
        </form>
      )}

      {/* QR Code Tab */}
      {activeTab === 'qr' && (
        <div className="qr-scanner-section">
          <div className="qr-options">
            {/* Upload Dropzone */}
            <div
              className={`qr-dropzone ${dragOver ? 'drag-over' : ''}`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
            >
              {qrPreview ? (
                <img src={qrPreview} alt="QR Preview" className="qr-preview-img" />
              ) : (
                <>
                  <div className="dropzone-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                      <polyline points="17 8 12 3 7 8"/>
                      <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                  </div>
                  <p className="dropzone-text">Drop QR code image here or click to upload</p>
                  <p className="dropzone-hint">Supports PNG, JPG, WEBP</p>
                </>
              )}
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileInput}
                style={{ display: 'none' }}
              />
            </div>

            {/* Camera Scanner */}
            <div className="qr-camera-section">
              {!cameraActive ? (
                <button className="camera-btn" onClick={startCamera}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                    <circle cx="12" cy="13" r="4"/>
                  </svg>
                  Open Camera Scanner
                </button>
              ) : (
                <div className="camera-view">
                  <video ref={videoRef} className="camera-video" playsInline muted />
                  <canvas ref={canvasRef} style={{ display: 'none' }} />
                  <div className="camera-overlay">
                    <div className="scan-corners">
                      <div className="corner tl"></div>
                      <div className="corner tr"></div>
                      <div className="corner bl"></div>
                      <div className="corner br"></div>
                    </div>
                    <p className="camera-hint">Point camera at QR code</p>
                  </div>
                  <button className="camera-stop-btn" onClick={stopCamera}>
                    Stop Camera
                  </button>
                </div>
              )}
            </div>
          </div>

          {loading && (
            <div className="qr-loading">
              <span className="spinner"></span>
              <span>Decoding & analyzing QR code...</span>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="error-card">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className={`result-card result-${result.threat_label?.toLowerCase()}`}>
          <div className="result-header">
            <div className="result-url">
              <span className="result-icon">{getLabelIcon(result.threat_label)}</span>
              <div>
                <h3>{result.url}</h3>
                <div className="result-meta">
                  <span className="result-domain">{result.domain}</span>
                  {result.scan_type === 'qr_scan' && (
                    <span className="scan-type-badge qr">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/>
                        <rect x="2" y="16" width="6" height="6" rx="1"/>
                      </svg>
                      QR Scan
                    </span>
                  )}
                </div>
              </div>
            </div>
            <div className="result-prediction">
              <span className={`prediction-badge prediction-${result.prediction?.toLowerCase()}`}>
                {result.prediction}
              </span>
            </div>
          </div>

          <div className="result-body">
            <div className="gauge-section">
              <ThreatGauge score={result.threat_score} label={result.threat_label} />
              <p className="gauge-description">
                {result.threat_label === 'SAFE' && 'This URL appears to be safe for browsing.'}
                {result.threat_label === 'WARN' && 'Proceed with caution. This URL shows suspicious patterns.'}
                {result.threat_label === 'BLOCK' && 'This URL is highly likely to be malicious. Do not proceed.'}
              </p>
            </div>

            {/* NLP Analysis Section */}
            {result.nlp_analysis && (
              <div className="nlp-section">
                <h4>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                  </svg>
                  NLP Content Analysis
                </h4>

                <div className="nlp-risk-header">
                  <span className="nlp-risk-label">NLP Risk Score</span>
                  <span className="nlp-risk-score" style={{ color: getNlpRiskColor(result.nlp_analysis.nlp_risk_score) }}>
                    {result.nlp_analysis.nlp_risk_score}/100
                  </span>
                </div>

                <div className="nlp-risk-bar-container">
                  <div
                    className="nlp-risk-bar"
                    style={{
                      width: `${result.nlp_analysis.nlp_risk_score}%`,
                      background: getNlpRiskColor(result.nlp_analysis.nlp_risk_score)
                    }}
                  ></div>
                </div>

                <div className="nlp-findings">
                  {result.nlp_analysis.summary?.map((finding, idx) => (
                    <div key={idx} className="nlp-finding-item">
                      <span className="nlp-finding-icon">
                        {finding.includes('No suspicious') ? '✅' : '⚡'}
                      </span>
                      <span>{finding}</span>
                    </div>
                  ))}
                </div>

                {/* NLP Detail Cards */}
                {result.nlp_analysis.details && Object.keys(result.nlp_analysis.details).length > 0 && (
                  <div className="nlp-details-grid">
                    {result.nlp_analysis.details.ngram_analysis?.suspicious_ngrams?.length > 0 && (
                      <div className="nlp-detail-card">
                        <h5>Suspicious Patterns</h5>
                        <div className="nlp-tags">
                          {result.nlp_analysis.details.ngram_analysis.suspicious_ngrams.map((ng, i) => (
                            <span key={i} className="nlp-tag danger">{ng}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {result.nlp_analysis.details.homoglyph_detection?.is_typosquatting && (
                      <div className="nlp-detail-card alert">
                        <h5>⚠️ Typosquatting Detected</h5>
                        <p>Possible impersonation of <strong>{result.nlp_analysis.details.homoglyph_detection.suspected_impersonation}</strong></p>
                      </div>
                    )}

                    {result.nlp_analysis.details.path_analysis?.anomalies?.length > 0 && (
                      <div className="nlp-detail-card">
                        <h5>Structural Anomalies</h5>
                        <div className="nlp-tags">
                          {result.nlp_analysis.details.path_analysis.anomalies.map((a, i) => (
                            <span key={i} className="nlp-tag warn">{a.replace(/_/g, ' ')}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {result.nlp_analysis.details.entropy_analysis && (
                      <div className="nlp-detail-card">
                        <h5>Entropy Analysis</h5>
                        <div className="nlp-entropy-stats">
                          <div className="entropy-stat">
                            <span className="entropy-label">Domain Entropy</span>
                            <span className={`entropy-value ${result.nlp_analysis.details.entropy_analysis.is_random_looking ? 'high' : ''}`}>
                              {result.nlp_analysis.details.entropy_analysis.domain_entropy}
                            </span>
                          </div>
                          <div className="entropy-stat">
                            <span className="entropy-label">URL Entropy</span>
                            <span className="entropy-value">
                              {result.nlp_analysis.details.entropy_analysis.url_entropy}
                            </span>
                          </div>
                          {result.nlp_analysis.details.entropy_analysis.is_random_looking && (
                            <span className="nlp-tag danger">Random-looking domain</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* SHAP Explanation Section */}
            {result.explanation && result.explanation.length > 0 && (
              <div className="explanation-section">
                <h4>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                  </svg>
                  XAI Explanation (SHAP Analysis)
                </h4>
                <div className="explanation-list">
                  {result.explanation.map((exp, idx) => (
                    <div key={idx} className={`explanation-item ${exp.direction}`}>
                      <span className="exp-icon">{getDirectionIcon(exp.direction)}</span>
                      <span className="exp-feature">{exp.feature.replace(/_/g, ' ')}</span>
                      <span className="exp-value">value: {exp.value}</span>
                      <div className="exp-bar-container">
                        <div
                          className={`exp-bar ${exp.direction}`}
                          style={{ width: `${Math.min(Math.abs(exp.impact) * 300, 100)}%` }}
                        ></div>
                      </div>
                      <span className="exp-impact">{exp.impact > 0 ? '+' : ''}{exp.impact.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.features && (
              <div className="features-section">
                <h4>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
                  </svg>
                  Extracted Features
                </h4>
                <div className="features-grid">
                  {Object.entries(result.features).map(([key, val]) => (
                    <div key={key} className="feature-chip">
                      <span className="feature-name">{key.replace(/_/g, ' ')}</span>
                      <span className="feature-value">{typeof val === 'number' ? val.toFixed(2) : val}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {result.reason && (
            <div className="result-footer">
              <span className="reason-tag">ℹ️ {result.reason}</span>
            </div>
          )}
        </div>
      )}

      <div className="quick-test">
        <h4>Quick Test URLs</h4>
        <div className="test-urls">
          {[
            { url: 'https://google.com', type: 'safe' },
            { url: 'http://192.168.1.1/login/verify-account', type: 'danger' },
            { url: 'http://paypal-secure-login.xyz/update', type: 'danger' },
            { url: 'https://github.com', type: 'safe' },
          ].map((item, idx) => (
            <button
              key={idx}
              className={`test-url-btn ${item.type}`}
              onClick={() => { setUrl(item.url); setActiveTab('url') }}
            >
              {item.url}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

export default Scanner
