import { useState, useEffect } from 'react'
import { getStats } from '../api'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, Legend
} from 'recharts'

const COLORS = {
  SAFE: '#10b981',
  WARN: '#f59e0b',
  BLOCK: '#ef4444',
}

function Analytics() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchStats = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getStats()
      setStats(data)
    } catch (err) {
      setError('Failed to fetch analytics. Make sure the API server is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  if (loading) {
    return (
      <div className="page analytics-page">
        <div className="page-header">
          <h1>Threat Analytics</h1>
          <p>Real-time threat intelligence dashboard</p>
        </div>
        <div className="loading-state">
          <div className="spinner large"></div>
          <p>Loading analytics...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page analytics-page">
        <div className="page-header">
          <h1>Threat Analytics</h1>
        </div>
        <div className="error-card">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      </div>
    )
  }

  const pieData = stats?.label_distribution
    ? Object.entries(stats.label_distribution).map(([name, value]) => ({
        name,
        value,
        color: COLORS[name] || '#6b7280'
      }))
    : []

  const dailyData = stats?.daily_scans || []
  const threatDomains = stats?.top_threat_domains || []

  return (
    <div className="page analytics-page">
      <div className="page-header">
        <h1>Threat Analytics</h1>
        <p>Real-time threat intelligence dashboard with visual insights</p>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon blue">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats?.total_scans || 0}</span>
            <span className="stat-label">Total Scans</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon green">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats?.label_distribution?.SAFE || 0}</span>
            <span className="stat-label">Safe URLs</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon yellow">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats?.label_distribution?.WARN || 0}</span>
            <span className="stat-label">Warnings</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>
              <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats?.label_distribution?.BLOCK || 0}</span>
            <span className="stat-label">Blocked</span>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        {/* Threat Distribution Pie */}
        <div className="chart-card">
          <h3>Threat Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: 'rgba(15, 23, 42, 0.95)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#e2e8f0'
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-chart">No data available</div>
          )}
        </div>

        {/* Daily Scans Line Chart */}
        <div className="chart-card">
          <h3>Scan Activity (Last 7 Days)</h3>
          {dailyData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={dailyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} />
                <YAxis stroke="#94a3b8" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(15, 23, 42, 0.95)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#e2e8f0'
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#6366f1"
                  strokeWidth={2}
                  dot={{ fill: '#6366f1', r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-chart">No scan data in the last 7 days</div>
          )}
        </div>

        {/* Top Threat Domains Bar */}
        <div className="chart-card wide">
          <h3>Top Threat Domains</h3>
          {threatDomains.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={threatDomains} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis type="number" stroke="#94a3b8" fontSize={12} />
                <YAxis
                  dataKey="domain"
                  type="category"
                  width={150}
                  stroke="#94a3b8"
                  fontSize={11}
                  tick={{ fill: '#94a3b8' }}
                />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(15, 23, 42, 0.95)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#e2e8f0'
                  }}
                />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-chart">No threat domains detected yet</div>
          )}
        </div>
      </div>

      {/* Average Score */}
      <div className="avg-score-card">
        <div className="avg-score-inner">
          <span className="avg-label">Average Threat Score</span>
          <span className="avg-value">{stats?.avg_threat_score || 0}</span>
          <span className="avg-label">across all scans</span>
        </div>
      </div>
    </div>
  )
}

export default Analytics
