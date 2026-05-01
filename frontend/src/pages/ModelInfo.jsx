import { useState, useEffect } from 'react'
import { getModelInfo } from '../api'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts'

function ModelInfo() {
  const [info, setInfo] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const data = await getModelInfo()
        setInfo(data)
      } catch (err) {
        setError('Failed to fetch model info. Make sure the API server is running.')
      } finally {
        setLoading(false)
      }
    }
    fetchInfo()
  }, [])

  if (loading) {
    return (
      <div className="page model-page">
        <div className="page-header"><h1>Model Information</h1></div>
        <div className="loading-state">
          <div className="spinner large"></div>
          <p>Loading model info...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page model-page">
        <div className="page-header"><h1>Model Information</h1></div>
        <div className="error-card"><span className="error-icon">⚠️</span><span>{error}</span></div>
      </div>
    )
  }

  const featureImportance = info?.global_feature_importance
    ? Object.entries(info.global_feature_importance)
        .map(([name, value]) => ({ name: name.replace(/_/g, ' '), value: parseFloat(value) }))
        .sort((a, b) => b.value - a.value)
    : []

  const evaluation = info?.evaluation || {}
  const bestModel = evaluation.best_model || 'Unknown'
  const rfMetrics = evaluation.random_forest || {}
  const xgbMetrics = evaluation.xgboost || {}

  return (
    <div className="page model-page">
      <div className="page-header">
        <h1>Model Information</h1>
        <p>AI model performance metrics and explainability insights</p>
      </div>

      {/* Best Model Badge */}
      <div className="best-model-card">
        <div className="best-model-icon">🏆</div>
        <div>
          <h2>Best Model: {bestModel}</h2>
          <p>Selected based on highest F1-Score</p>
        </div>
        <div className="shap-badge">
          {info?.shap_available ? '🔍 SHAP Active' : '⚠️ SHAP Unavailable'}
        </div>
      </div>

      {/* Model Comparison Table */}
      {(rfMetrics.accuracy || xgbMetrics.accuracy) && (
        <div className="comparison-card">
          <h3>Model Comparison</h3>
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Random Forest</th>
                {xgbMetrics.accuracy && <th>XGBoost</th>}
              </tr>
            </thead>
            <tbody>
              {['accuracy', 'precision', 'recall', 'f1_score'].map((metric) => {
                const rfVal = rfMetrics[metric]
                const xgbVal = xgbMetrics[metric]
                const rfBetter = rfVal >= (xgbVal || 0)

                return (
                  <tr key={metric}>
                    <td className="metric-name">{metric.replace('_', ' ').toUpperCase()}</td>
                    <td className={rfBetter ? 'best-value' : ''}>
                      {rfVal !== undefined ? (rfVal * 100).toFixed(2) + '%' : '—'}
                      {rfBetter && ' 🏆'}
                    </td>
                    {xgbMetrics.accuracy && (
                      <td className={!rfBetter ? 'best-value' : ''}>
                        {xgbVal !== undefined ? (xgbVal * 100).toFixed(2) + '%' : '—'}
                        {!rfBetter && ' 🏆'}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Confusion Matrix */}
      {rfMetrics.confusion_matrix && (
        <div className="confusion-card">
          <h3>Confusion Matrix (Best Model)</h3>
          <div className="confusion-matrix">
            <div className="cm-header-row">
              <div className="cm-empty"></div>
              <div className="cm-header">Predicted Safe</div>
              <div className="cm-header">Predicted Phishing</div>
            </div>
            <div className="cm-row">
              <div className="cm-label">Actual Safe</div>
              <div className="cm-cell tn">
                <span className="cm-value">{bestModel === 'Random Forest' ? rfMetrics.confusion_matrix[0][0] : xgbMetrics.confusion_matrix?.[0]?.[0]}</span>
                <span className="cm-tag">TN</span>
              </div>
              <div className="cm-cell fp">
                <span className="cm-value">{bestModel === 'Random Forest' ? rfMetrics.confusion_matrix[0][1] : xgbMetrics.confusion_matrix?.[0]?.[1]}</span>
                <span className="cm-tag">FP</span>
              </div>
            </div>
            <div className="cm-row">
              <div className="cm-label">Actual Phishing</div>
              <div className="cm-cell fn">
                <span className="cm-value">{bestModel === 'Random Forest' ? rfMetrics.confusion_matrix[1][0] : xgbMetrics.confusion_matrix?.[1]?.[0]}</span>
                <span className="cm-tag">FN</span>
              </div>
              <div className="cm-cell tp">
                <span className="cm-value">{bestModel === 'Random Forest' ? rfMetrics.confusion_matrix[1][1] : xgbMetrics.confusion_matrix?.[1]?.[1]}</span>
                <span className="cm-tag">TP</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Feature Importance Chart */}
      {featureImportance.length > 0 && (
        <div className="importance-card">
          <h3>SHAP Feature Importance</h3>
          <p className="chart-description">Average absolute SHAP values — higher means more influence on predictions</p>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={featureImportance} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis type="number" stroke="#94a3b8" fontSize={12} />
              <YAxis
                dataKey="name"
                type="category"
                width={120}
                stroke="#94a3b8"
                fontSize={12}
              />
              <Tooltip
                contentStyle={{
                  background: 'rgba(15, 23, 42, 0.95)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#e2e8f0'
                }}
                formatter={(val) => val.toFixed(4)}
              />
              <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Feature List */}
      <div className="features-info-card">
        <h3>Extracted Features ({info?.feature_names?.length || 0})</h3>
        <div className="feature-tags">
          {(info?.feature_names || []).map((name, idx) => (
            <span key={idx} className="feature-tag">{name.replace(/_/g, ' ')}</span>
          ))}
        </div>
      </div>
    </div>
  )
}

export default ModelInfo
