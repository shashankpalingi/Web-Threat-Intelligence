import { useEffect, useState } from 'react'

function ThreatGauge({ score, label }) {
  const [animatedScore, setAnimatedScore] = useState(0)

  useEffect(() => {
    let start = 0
    const end = score
    const duration = 1200
    const stepTime = 16
    const steps = duration / stepTime
    const increment = end / steps

    const timer = setInterval(() => {
      start += increment
      if (start >= end) {
        start = end
        clearInterval(timer)
      }
      setAnimatedScore(Math.round(start * 10) / 10)
    }, stepTime)

    return () => clearInterval(timer)
  }, [score])

  const getColor = () => {
    if (score <= 30) return { main: '#10b981', glow: 'rgba(16, 185, 129, 0.3)' }
    if (score <= 70) return { main: '#f59e0b', glow: 'rgba(245, 158, 11, 0.3)' }
    return { main: '#ef4444', glow: 'rgba(239, 68, 68, 0.3)' }
  }

  const color = getColor()

  // SVG arc calculation
  const radius = 80
  const circumference = Math.PI * radius // half circle
  const progress = (animatedScore / 100) * circumference

  return (
    <div className="threat-gauge">
      <svg width="200" height="120" viewBox="0 0 200 120">
        {/* Background arc */}
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke={color.main}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{
            filter: `drop-shadow(0 0 8px ${color.glow})`,
            transition: 'stroke-dasharray 0.3s ease'
          }}
        />
      </svg>
      <div className="gauge-value" style={{ color: color.main }}>
        {animatedScore}
      </div>
      <div className="gauge-label">
        <span className={`threat-badge threat-${label?.toLowerCase()}`}>
          {label}
        </span>
      </div>
    </div>
  )
}

export default ThreatGauge
