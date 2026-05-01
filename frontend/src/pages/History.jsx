import { useState, useEffect } from 'react'
import { getHistory } from '../api'

function History() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState(null)
  const [error, setError] = useState(null)

  const fetchHistory = async (label = null) => {
    setLoading(true)
    setError(null)
    try {
      const data = await getHistory(100, 0, label)
      setScans(data.scans || [])
    } catch (err) {
      setError('Failed to fetch scan history. Make sure the API server is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory(filter)
  }, [filter])

  const formatDate = (timestamp) => {
    if (!timestamp) return '—'
    const d = new Date(timestamp + 'Z')
    return d.toLocaleString()
  }

  const getLabelIcon = (label) => {
    switch (label) {
      case 'SAFE': return '✅'
      case 'WARN': return '⚠️'
      case 'BLOCK': return '🚫'
      default: return '❓'
    }
  }

  return (
    <div className="page history-page">
      <div className="page-header">
        <h1>Scan History</h1>
        <p>Audit trail of all analyzed URLs with threat classifications</p>
      </div>

      <div className="history-controls">
        <div className="filter-buttons">
          <button
            id="filter-all"
            className={`filter-btn ${filter === null ? 'active' : ''}`}
            onClick={() => setFilter(null)}
          >
            All
          </button>
          <button
            id="filter-safe"
            className={`filter-btn safe ${filter === 'SAFE' ? 'active' : ''}`}
            onClick={() => setFilter('SAFE')}
          >
            ✅ Safe
          </button>
          <button
            id="filter-warn"
            className={`filter-btn warn ${filter === 'WARN' ? 'active' : ''}`}
            onClick={() => setFilter('WARN')}
          >
            ⚠️ Warn
          </button>
          <button
            id="filter-block"
            className={`filter-btn block ${filter === 'BLOCK' ? 'active' : ''}`}
            onClick={() => setFilter('BLOCK')}
          >
            🚫 Block
          </button>
        </div>
        <button className="refresh-btn" onClick={() => fetchHistory(filter)}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          Refresh
        </button>
      </div>

      {error && (
        <div className="error-card">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="loading-state">
          <div className="spinner large"></div>
          <p>Loading scan history...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M8 12h8"/><path d="M12 8v8"/>
          </svg>
          <h3>No Scans Yet</h3>
          <p>Go to the URL Scanner to analyze your first URL</p>
        </div>
      ) : (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>URL</th>
                <th>Domain</th>
                <th>Threat Score</th>
                <th>Label</th>
                <th>Confidence</th>
                <th>Scanned At</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className={`row-${scan.threat_label?.toLowerCase()}`}>
                  <td className="status-cell">
                    <span className="status-icon">{getLabelIcon(scan.threat_label)}</span>
                  </td>
                  <td className="url-cell" title={scan.url}>
                    {scan.url?.length > 60 ? scan.url.slice(0, 60) + '...' : scan.url}
                  </td>
                  <td className="domain-cell">{scan.domain}</td>
                  <td className="score-cell">
                    <div className="score-bar-container">
                      <div
                        className={`score-bar ${scan.threat_label?.toLowerCase()}`}
                        style={{ width: `${scan.threat_score}%` }}
                      ></div>
                    </div>
                    <span className="score-value">{scan.threat_score}</span>
                  </td>
                  <td>
                    <span className={`threat-badge threat-${scan.threat_label?.toLowerCase()}`}>
                      {scan.threat_label}
                    </span>
                  </td>
                  <td>{scan.confidence ? (scan.confidence * 100).toFixed(1) + '%' : '—'}</td>
                  <td className="date-cell">{formatDate(scan.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default History
