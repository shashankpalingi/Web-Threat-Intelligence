import { useState } from 'react'
import { checkUrl } from '../api'
import ThreatGauge from '../components/ThreatGauge'

function Scanner() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

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

  return (
    <div className="page scanner-page">
      <div className="page-header">
        <h1>URL Threat Scanner</h1>
        <p>Analyze any URL for phishing, scams, and malicious content using AI</p>
      </div>

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
                <span className="result-domain">{result.domain}</span>
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

            {result.explanation && result.explanation.length > 0 && (
              <div className="explanation-section">
                <h4>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                  </svg>
                  AI Explanation (SHAP Analysis)
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
              onClick={() => setUrl(item.url)}
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
